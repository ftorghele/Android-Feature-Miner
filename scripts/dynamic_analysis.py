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

import sys, io, os.path, subprocess, json, hashlib, time, re

from optparse import OptionParser
from pymongo import MongoClient

current_dir       = os.path.dirname(sys.argv[0])
client            = MongoClient('localhost', 6662)
db                = client.androsom
filehash          = None
apk_package       = ""
apk_main_activity = ""
static_analysis   = None
durations         = {}
monkey_errors     = {}

method_calls      = {}
accessed_files    = {}
opened_files      = {}
chmoded_files     = {}

valid_analysis    = True
min_valid_runs    = 2

monkey_steps      = 1250
monkey_min_time   = 60
monkey_max_time   = 100
monkey_trys       = 3
monkey_runs       = 4

def hashfile(filepath) :
    global filehash

    if filehash != None :
        return filehash

    collection = db.file_hashes
    data       = collection.find_one({"path": filepath})

    if data == None :
        sha1 = hashlib.sha1()
        f = open(filepath, 'rb')
        try:
            sha1.update(f.read())
        finally:
            f.close()
        filehash = sha1.hexdigest()

        data = {
            'path' : filepath,
            'hash' : filehash
        }
        collection.insert(data)
    else :
        filehash = data.get('hash')

    return filehash

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

def install_apk() :
    print_info("Installing APK..")
    call("adb install " + options.input)

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

def monkey() :
    global durations, monkey_errors, valid_analysis

    valid_count = 0

    for i in xrange(0, monkey_runs) :
        duration = run_monkey(i)

        if duration < monkey_min_time or duration > monkey_max_time :
            monkey_errors["monkey_"+str(i)+"_try_0"] = "monkey duration not between min("+ str(monkey_min_time) +"sec) and max("+ str(monkey_max_time) +"sec): " + str(duration) + " sec."
            print monkey_errors.get("monkey_"+str(i)+"_try_0")
            for e in xrange(1, monkey_trys) :
                if duration >= monkey_min_time and duration <= monkey_max_time :
                    continue
                else :
                    duration = run_monkey(i)
                    if duration < monkey_min_time or duration > monkey_max_time :
                         monkey_errors["monkey_"+str(i)+"_try_"+str(e)] = "monkey duration not between min("+ str(monkey_min_time) +"sec) and max("+ str(monkey_max_time) +"sec): " + str(duration) + " sec."
                         print monkey_errors.get("monkey_"+str(i)+"_try_"+str(e))


        if duration >= monkey_min_time and duration <= monkey_max_time :
            durations["monkey_"+str(i)] = duration
            valid_count += 1
        else :
            durations["monkey_"+str(i)] = False

    if valid_count < min_valid_runs :
        valid_analysis = False


def run_monkey(i) :
    t_begin = time.time()
    print_info("Run monkey with strace.. run " + str(i+1) + " of " + str(monkey_runs))
    call("adb shell sh /data/local/tasks.sh monkey " + apk_package + " " + str(monkey_steps) + " _" + str(i))
    return time.time() - t_begin
        
def pull_data() :
    print_info("Pulling data..")
    call(current_dir + "/ftp.sh start " + current_dir + "/../tmp")
    call("adb shell sh /data/local/tasks.sh transfer")
    call(current_dir + "/ftp.sh stop " + current_dir + "/../tmp")

def fix_pcap() :
    print_info("Fixing pcap file..")
    call("cd " + current_dir + "/../tmp && pcapfix --deep-scan " + current_dir + "/../tmp/tcpdump.pcap")
    if os.path.isfile(current_dir + "/../tmp/fixed_tcpdump.pcap") :
        call("mv -f " + current_dir + "/../tmp/fixed_tcpdump.pcap " + current_dir + "/../tmp/tcpdump.pcap")    

def get_accessed_hostnames() :
    print_info("Get accessed hostnames..")
    result = []
    cmd    = "tshark -2 -r  " + current_dir + "/../tmp/tcpdump.pcap -R \"dns.flags.response == 0\" -T fields -e dns.qry.name -e dns.qry"
    output = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=None, shell=True).communicate()
    for line in output[0].split(os.linesep) :
        if line != "" :
            result.append(line.strip())
    return result

def get_accessed_ips() :
    print_info("Get accessed ips..")
    result = []
    cmd    = "tshark -r " + current_dir + "/../tmp/tcpdump.pcap -T fields -e ip.dst ip.src | sort | uniq"
    output = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=None, shell=True).communicate()
    for line in output[0].split(os.linesep) :
        if line != "" :
            result.append(line)
    return result

def analyse_strace() :
    global method_calls, accessed_files, opened_files, chmoded_files, durations
    print_info("Analyse strace logs..")

    t_begin = time.time()

    call("cd " + current_dir + "/../tmp && cat ./strace_*.log >> ./strace_all.log")
    strace = open( current_dir + "/../tmp/strace_all.log", "r" )
    for line in strace:
        line = line.strip()

        method = re.split("\s+|\(", line)
        if method[1] not in method_calls :
            method_calls[method[1]] = 1
        else :
            method_calls[method[1]] += 1

        if method[1] == "open" or method[1] == "access" or method[1] == "chmod" :
            path = re.split('open\("|access\("|chmod\("|"', line)
            path = path[1].replace('.', "_")

            if method[1] == "access" :
                if path not in accessed_files :
                    accessed_files[path] = 1
                else :
                    accessed_files[path] += 1

            if method[1] == "chmod" :
                if path not in chmoded_files :
                    chmoded_files[path] = 1
                else :
                    chmoded_files[path] += 1

            if method[1] == "open" :
                if path not in opened_files :
                    opened_files[path] = 1
                else :
                    opened_files[path] += 1

    strace.close()
    durations["analyse_strace"] = time.time() - t_begin

def save_data() :
    call("mv -f " + current_dir + "/../tmp/tcpdump.pcap " + options.output + "/" + hashfile(options.input) + ".pcap")
    for i in xrange(0, monkey_runs) :
        call("mv -f " + current_dir + "/../tmp/strace_" + str(i) + ".log " + options.output + "/" + hashfile(options.input) + "_" + str(i) + ".strace")

def print_info(msg) :
    print "\n-------------------------------------------------------------------------------"
    print "### " + msg
    print "-------------------------------------------------------------------------------\n"

def main(options, args) :
    global apk_main_activity, apk_package, durations

    print_info("Analysis of: " + options.input)
    if options.input == None or options.output == None :
        print "dynamic_analysis.py -i <inputfile> -o <outputfolder>"
        sys.exit(2)
    elif db.dynamic_features.find({"_id": hashfile(options.input)}).count() > 0 :
        print "dynamic analysis found.. skipping.."
        sys.exit(0)
    elif db.virustotal_features.find({"sha1": hashfile(options.input)}).count() == 0 :
        print "virus total metadata not found.. skipping.."
        sys.exit(0)
    elif db.virustotal_features.find({ "$or": [ { "positives": 0 }, { "positives": { "$gte": 35 } } ], "sha1": hashfile(options.input) }).count() == 0 :
        print "not clear enough benign or malicious.. skipping.."
        sys.exit(0)
    elif db.static_features.find({"_id": hashfile(options.input)}).count() == 0 :
        print "static analysis not found.. skipping.."
        sys.exit(0)
    else :
        static_analysis   = db.static_features.find_one({"_id": hashfile(options.input)})
        apk_package       = static_analysis.get("package")
        apk_main_activity = static_analysis.get("mainActivity")  

    print "package:\t" + apk_package
    print "main activity:\t" + apk_main_activity

    t_all_beginning = time.time()

    clean_state()
    start_vm()
    connect_adb()
    push_tasks()
    start_tcpdump()
    install_apk()
    monkey()
    stop_tcpdump()
    pull_data()
    stop_vm()
    fix_pcap()
    analyse_strace()

    durations["all"] = time.time() - t_all_beginning,

    data = {
        '_id'               : hashfile(options.input),
        'valid'             : valid_analysis,
        'durations'         : durations,
        'monkeyErrors'      : monkey_errors,
        'accessedHostnames' : get_accessed_hostnames(),
        'accessedIps'       : get_accessed_ips(),
        'methodCalls'       : method_calls,
        'accessedFiles'     : accessed_files,
        'openedFiles'       : opened_files,
        'chmodedFiles'      : chmoded_files
    }

    db.dynamic_features.insert(data)

    save_data()

    print_info("Analysis finished.")

if __name__ == "__main__" :
    parser = OptionParser()
    parser.add_option("-i", "--input", dest="input", help="path to the APK file which shoud be analysed.")
    parser.add_option("-o", "--output", dest="output", help="folder to store pulled files.")
    (options, args) = parser.parse_args()

    sys.argv[:] = args
    main(options, args)
