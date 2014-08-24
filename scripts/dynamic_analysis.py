#!/usr/bin/env python
#
# ----------------------------------------------------------------------------------
# This file is part of {@link https://github.com/AndroSOM/FeatureMiner AndroSOM}.
#
# Copyright (c) 2014 AndroSOM
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.
# ----------------------------------------------------------------------------------

import sys, io, os.path, subprocess, json, hashlib, time
from optparse import OptionParser

current_dir = os.path.dirname(sys.argv[0])

def hashfile(filepath) :
    sha1 = hashlib.sha1()
    f = open(filepath, 'rb')
    try:
        sha1.update(f.read())
    finally:
        f.close()
    return sha1.hexdigest()

def call(cmd) :
    subprocess.Popen(cmd, stdout=None, stderr=None, shell=True).wait()

def clean_state() :
    print_info("Restoring clean state..")
    call("rm -rf " + current_dir + "/../tmp/*")
    call("VBoxManage snapshot AndroidVM restore cleanstate")

def start_vm() :
    print_info("Starting Android VM..")
    call("VBoxManage startvm AndroidVM")

def stop_vm() :
    print_info("Stopping Android VM..")
    call("VBoxManage controlvm AndroidVM poweroff")

def connect_adb() :
    print_info("Connecting ADB..")
    call("adb kill-server")
    time.sleep(2.5)
    call("adb connect 127.0.0.1:6666")
    call("adb wait-for-device")

def install_apk(apk_path) :
    print_info("Installing APK..")
    call("adb install " + apk_path)

def push_tasks() : 
    print_info("Uploading tasks to Android..")
    call("adb push " + current_dir + "/tasks.sh /data/local/tasks.sh")
    call("adb shell chmod 777 /data/local/tasks.sh")
    call("adb shell sh /data/local/tasks.sh prepare")

def start_tcpdump() :
    print_info("Starting tcpdump..")
    call("adb shell sh /data/local/tasks.sh tcpdump start")

def stop_tcpdump() :
    print_info("Stopping tcpdump..")
    call("adb shell sh /data/local/tasks.sh tcpdump stop")

def pull_data() :
    print_info("Pulling data..")
    call(current_dir + "/ftp.sh start " + current_dir + "/../tmp")
    call("adb shell sh /data/local/tasks.sh transfer")
    call(current_dir + "/ftp.sh stop " + current_dir + "/../tmp")
    call("cd " + current_dir + "/../tmp/ && tar -xzvf features.tar.gz")

def fix_pcap() :
    print_info("Fixing pcap file..")
    call("cd " + current_dir + "/../tmp && pcapfix --deep-scan " + current_dir + "/../tmp/tcpdump.pcap")
    if os.path.isfile(current_dir + "/../tmp/fixed_tcpdump.pcap") :
        call("mv -f " + current_dir + "/../tmp/fixed_tcpdump.pcap " + current_dir + "/../tmp/tcpdump.pcap")

def get_accessed_hostnames() :
    result = []
    cmd    = "tshark -2 -r  " + current_dir + "/../tmp/tcpdump.pcap -R \"dns.flags.response == 0\" -T fields -e dns.qry.name -e dns.qry"
    output = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=None, shell=True).communicate()
    for line in output[0].split(os.linesep) :
        if line != "" :
            result.append(line.strip())
    return result

def get_accessed_ips() :
    result = []
    cmd    = "tshark -r " + current_dir + "/../tmp/tcpdump.pcap -T fields -e ip.dst ip.src | sort | uniq"
    output = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=None, shell=True).communicate()
    for line in output[0].split(os.linesep) :
        if line != "" :
            result.append(line)
    return result

def print_info(msg) :
    print "\n-------------------------------------------------------------------------------"
    print "### " + msg
    print "-------------------------------------------------------------------------------\n"

def main(options, args) :
    print_info("Analysis of: " + options.input)
    if options.input == None or options.output == None :
        print "dynamic_analysis.py -i <inputfile> -o <outputfolder>"
        sys.exit(2)
    else :
        analysis_file_path = options.output + "/" + hashfile(options.input)

        apk_package          = ""
        apk_main_activity    = ""
        static_analysis_data = []

        #if os.path.isfile(analysis_file_path + "_dynamic.json") :
        #    print "dynamic analysis found.. skipping.."
        #elif ...
        if os.path.isfile(analysis_file_path + "_static.json") :
            fh                   = open(analysis_file_path + "_static.json")
            static_analysis_data = json.load(fh)

            apk_package          = static_analysis_data.get("package", None)
            apk_main_activity    = static_analysis_data.get("mainActivity", None)

            fh.close()
        else :
            command           = "aapt dump badging " + options.input + " | awk -F\" \" '/package/ {print $2}' | awk -F\"'\" '/name=/ {print $2}'"
            apk_package       = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=None, shell=True).communicate()[0].rstrip()
            command           = "aapt dump badging " + options.input + " | awk -F\" \" '/launchable activity/ {print $3}' | awk -F\"'\" '/name=/ {print $2}'"
            apk_main_activity = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=None, shell=True).communicate()[0].rstrip()

        print "package:\t" + apk_package
        print "main activity:\t" + apk_main_activity

        t_beginning = time.time()

        clean_state()
        start_vm()
        connect_adb()
        push_tasks()
        start_tcpdump()
        install_apk(options.input)
        time.sleep(30)
        stop_tcpdump()
        pull_data()
        stop_vm()

        fix_pcap()

        t_ending = time.time()

        data = {
            'duration'          : t_ending - t_beginning,
            'accessedHostnames' : get_accessed_hostnames(),
            'accessedIps'       : get_accessed_ips()
        }

        with io.open(options.output + "/" + hashfile(options.input) + "_dynamic.json", 'w', encoding='utf-8') as f:
            f.write(unicode(json.dumps(data, sort_keys=False, indent=2, separators=(',', ': '), ensure_ascii=False)))
    

        print_info("Analysis finished.")



if __name__ == "__main__" :
    parser = OptionParser()
    parser.add_option("-i", "--input", dest="input", help="path to the APK file which shoud be analysed.")
    parser.add_option("-o", "--output", dest="output", help="folder to write the analysis result as json.")
    (options, args) = parser.parse_args()

    sys.argv[:] = args
    main(options, args)
