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

import sys, io, os.path, subprocess, json, hashlib, time, re, threading, thread

from optparse import OptionParser
from pymongo import MongoClient

current_dir       = os.path.dirname(sys.argv[0])
client            = MongoClient('localhost', 6662)
db                = client.androsom
filehash          = None
broadcasts        = {}
static_features   = None
apk_package       = ""
apk_main_activity = ""
durations         = {}
errors            = {}
file_state        = {}

method_calls      = {}
accessed_files    = {}
opened_files      = {}
chmoded_files     = {}

valid_analysis    = True
timed_out         = False

monkey_steps      = 1250
monkey_min_time   = 60  #sec
monkey_max_time   = 100 #sec
monkey_trys       = 5
monkey_runs       = 4
min_valid_runs    = 4

timeout_after     = 600 #sec

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
    call("adb kill-server")

def connect_adb() :
    print_info("Connecting ADB..")
    call("killall adb")
    time.sleep(2.5)
    call("adb connect 127.0.0.1:6666")
    call("adb wait-for-device")

def install_apk() :
    print_info("Installing APK..")
    call("adb install '" + options.input + "'")

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

def start_logcat() :
    print_info("Starting logcat..")
    call("cd " + current_dir + "/../tmp/ && nohup adb logcat -b radio > ./radio.log &")
    call("cd " + current_dir + "/../tmp/ && nohup adb logcat -b events > ./events.log &")
    call("cd " + current_dir + "/../tmp/ && nohup adb logcat -b main > ./logcat.log &")

def monkey() :
    global durations, errors, valid_analysis

    valid_count = 0

    for i in xrange(0, monkey_runs) :
        durations["monkey_"+str(i)] = False
        for e in xrange(0, monkey_trys) :
            if durations["monkey_"+str(i)] != False :
                continue

            if check_if_remote_file_exists("/sdcard/features/strace_" + str(i) + ".log") :
                call("adb shell sh /data/local/tasks.sh clear_strace _" + str(i))

            duration = run_monkey(i, e)
            durations["monkey_"+str(i)] = duration

            if duration < monkey_min_time :
                errors["monkey_"+str(i)+"_try_"+str(e)] = "monkey duration beneath min("+ str(monkey_min_time) +"sec): " + str(duration) + " sec."
            elif duration > monkey_max_time :
                errors["monkey_"+str(i)+"_try_"+str(e)] = "monkey duration above max("+ str(monkey_max_time) +"sec): " + str(duration) + " sec."
            elif check_if_remote_file_exists("/sdcard/features/strace_" + str(i) + ".log") == False :
                errors["monkey_"+str(i)+"_try_"+str(e)] = "no strace log found.."

            if errors.get("monkey_"+str(i)+"_try_"+str(e)) :
                print errors.get("monkey_"+str(i)+"_try_"+str(e))
                durations["monkey_"+str(i)] = False
            else :
                durations["monkey_"+str(i)] = duration
                valid_count += 1          

    if valid_count < min_valid_runs :
        valid_analysis = False


def run_monkey(run_count, try_count) :
    thread.start_new_thread(send_broadcasts, (run_count, try_count))
    #thread.start_new_thread(send_activities, (run_count, try_count))
    
    t_begin = time.time()
    print_info("Run monkey with strace.. run " + str(run_count+1) + " of " + str(monkey_runs) + " try " + str(try_count))
    call("adb shell sh /data/local/tasks.sh monkey " + apk_package + " " + str(monkey_steps) + " " + str(run_count))
    t_end = time.time()

    call("adb shell am force-stop " + apk_package)
    time.sleep(2)
    return t_end - t_begin

def check_if_remote_file_exists(path) :
    output = subprocess.Popen("adb shell ls " + path, stdout=subprocess.PIPE, stderr=None, shell=True).communicate()
    if output[0].strip() == path :
        return True
    else :
        return False
   
def pull_data() :
    print_info("Pulling data..")
    call(current_dir + "/ftp.sh start " + current_dir + "/../tmp")
    call("adb shell sh /data/local/tasks.sh transfer")
    call(current_dir + "/ftp.sh stop " + current_dir + "/../tmp")

def fix_pcap() :
    print_info("Fixing pcap file..")
    if os.path.isfile(current_dir + "/../tmp/tcpdump.pcap") :
        call("cd " + current_dir + "/../tmp && pcapfix --deep-scan " + current_dir + "/../tmp/tcpdump.pcap")
        if os.path.isfile(current_dir + "/../tmp/fixed_tcpdump.pcap") :
            call("mv -f " + current_dir + "/../tmp/fixed_tcpdump.pcap " + current_dir + "/../tmp/tcpdump.pcap")    

def get_accessed_hostnames() :
    print_info("Get accessed hostnames..")
    result = []
    if os.path.isfile(current_dir + "/../tmp/tcpdump.pcap") :
        cmd    = "tshark -2 -r  " + current_dir + "/../tmp/tcpdump.pcap -R \"dns.flags.response == 0\" -T fields -e dns.qry.name -e dns.qry | sort | uniq"
        output = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=None, shell=True).communicate()
        for line in output[0].split(os.linesep) :
            if line != "" :
                result.append(line.strip())
    return result

def get_accessed_ips() :
    print_info("Get accessed ips..")
    result = []
    if os.path.isfile(current_dir + "/../tmp/tcpdump.pcap") :
        cmd    = "tshark -r " + current_dir + "/../tmp/tcpdump.pcap -T fields -e ip.dst ip.src | sort | uniq"
        output = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=None, shell=True).communicate()
        for line in output[0].split(os.linesep) :
            if line != "" :
                result.append(line)
    return result

def get_broadcasts() :
    global broadcasts
    print_info("Get broadcasts..")

    possible_broadcasts = []
    fh = open( current_dir + "/broadcast_action_list.txt", "r" )
    for line in fh:
        possible_broadcasts.append(line.strip())

    cmd    = "aapt l -a '" + options.input + "'"
    output = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=None, shell=True).communicate()

    receiver_on_next_line = False
    current_receiver_name = None
    for line in output[0].split(os.linesep) :
        if re.search('E: receiver', line) :
            receiver_on_next_line = True
            continue
        raw = re.search('Raw: "([\w.]*)"', line)
        if raw == None :
            continue
        if receiver_on_next_line :
            receiver_on_next_line = False
            receiver_name = raw.group(1)
            if receiver_name not in broadcasts:
                broadcasts[receiver_name] = []
                current_receiver_name = receiver_name
                continue
        if current_receiver_name != None and raw.group(1) in possible_broadcasts :
            broadcasts[current_receiver_name].append(raw.group(1))

def send_broadcasts(run_count, try_count) :
    time.sleep(5)
    for receiver_class in broadcasts :
        for broadcast in broadcasts[receiver_class] :
            if (errors.get("monkey_"+str(run_count)+"_try_"+str(try_count)) == None) and (durations.get("monkey_"+str(run_count+1)) == None) :
                call("adb shell am broadcast -a " + broadcast + " -n " + apk_package + "/" + receiver_class)
            else :
                thread.exit()

def send_activities(run_count, try_count) :
    time.sleep(5)
    for activity in static_features.get('activities') :
        time.sleep(3)
        if (errors.get("monkey_"+str(run_count)+"_try_"+str(try_count)) == None) and (durations.get("monkey_"+str(run_count+1)) == None) :
            call("adb shell am start -n " + apk_package + "/" + activity)
        else :
            thread.exit()

def check_data() :
    global errors, valid_analysis
    print_info("Checking files..")

    files = ['tcpdump.pcap', 'radio.log', 'events.log', 'logcat.log']
    for filename in files :
        if os.path.isfile(current_dir + "/../tmp/" + filename) == False :
            errors[filename.replace('.', "_")] = "not found"
            valid_analysis = False
    for i in xrange(0, monkey_runs) :
        if os.path.isfile(current_dir + "/../tmp/strace_" + str(i) + ".log") == False :
            errors["strace_" + str(i) + "_log"] = "not found"
            valid_analysis = False

            
def analyse_strace() :
    global method_calls, accessed_files, opened_files, chmoded_files, durations
    print_info("Analyse strace logs..")

    t_begin = time.time()

    call("cd " + current_dir + "/../tmp && cat ./strace_*.log >> ./strace_all.log")
    if os.path.isfile(current_dir + "/../tmp/strace_all.log") :
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

                path = path.replace("/data/data/" + apk_package.replace('.', "_") + "/", "", 1)

                if re.search('/proc/\d*/task/\d*/stat', path) :
                    path = "/proc/id/task/id/stat"

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
        call("cd " + current_dir + "/../tmp && rm -f ./strace_all.log")

    durations["analyse_strace"] = time.time() - t_begin

def save_data() :
    print_info("Saving data..")
    call("rm -Rf " + options.output + "/" + hashfile(options.input))
    call("cp -Rf " + current_dir + "/../tmp " + options.output + "/" + hashfile(options.input))

    data = {
        '_id'               : hashfile(options.input),
        'valid'             : valid_analysis,
        'timeout'           : timed_out,
        'durations'         : durations,
        'errors'            : errors,
        'accessedHostnames' : get_accessed_hostnames(),
        'accessedIps'       : get_accessed_ips(),
        'methodCalls'       : method_calls,
        'accessedFiles'     : accessed_files,
        'openedFiles'       : opened_files,
        'chmodedFiles'      : chmoded_files
    }

    db.dynamic_features.insert(data)

def timeout(t_all_begin) :
    global durations, timed_out
    time.sleep(timeout_after)

    call("killall adb")
    stop_vm()
    check_data()

    durations["all"] = time.time() - t_all_begin
    timed_out = True

    save_data()
    thread.interrupt_main()

def print_info(msg) :
    print "\n-------------------------------------------------------------------------------"
    print "### " + msg
    print "-------------------------------------------------------------------------------\n"

def main(options, args) :
    global apk_main_activity, apk_package, durations, static_features

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
        static_features   = db.static_features.find_one({"_id": hashfile(options.input)})
        apk_package       = static_features.get('package')
        apk_main_activity = static_features.get('mainActivity')

    if apk_main_activity == None or apk_package == None :
        print "Package or main activity not found.. skipping.."
        sys.exit(0)

    print "package:\t" + apk_package
    print "main activity:\t" + apk_main_activity

    t_all_begin = time.time()

    thread.start_new_thread(timeout, (t_all_begin, ))

    get_broadcasts()
    clean_state()
    start_vm()
    connect_adb()
    push_tasks()
    start_tcpdump()
    start_logcat()
    install_apk()
    monkey()
    stop_tcpdump()
    pull_data()
    stop_vm()
    check_data()
    fix_pcap()
    analyse_strace()

    durations["all"] = time.time() - t_all_begin

    save_data()

    print_info("Analysis finished.")

if __name__ == "__main__" :
    parser = OptionParser()
    parser.add_option("-i", "--input", dest="input", help="path to the APK file which shoud be analysed.")
    parser.add_option("-o", "--output", dest="output", help="folder to store pulled files.")
    (options, args) = parser.parse_args()

    sys.argv[:] = args
    try:
        main(options, args)
    except KeyboardInterrupt:
        print_info("Timeout..")
    
