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

import sys, os.path, subprocess, json, hashlib, time

from optparse import OptionParser

def hashfile(filepath) :
    sha1 = hashlib.sha1()
    f = open(filepath, 'rb')
    try:
        sha1.update(f.read())
    finally:
        f.close()
    return sha1.hexdigest()

def call(command) :
    subprocess.Popen(command, stdout=subprocess.PIPE, stderr=None, shell=True).wait()

def clean_state() :
    print "\tRestoring clean state.."
    call("VBoxManage snapshot AndroidVM restore cleanstate")

def start_vm() :
    print "\tStarting Android VM.."
    call("VBoxManage startvm AndroidVM")

def stop_vm() :
    print "\tStopping Android VM.."
    call("VBoxManage controlvm AndroidVM poweroff")

def connect_adb() :
    print "\tConnecting ADB.."
    time.sleep(5)
    call("adb kill-server")
    call("adb connect 127.0.0.1:6666")
    call("adb wait-for-device")

def install_apk(apk_path) :
    print "\tInstalling APK.."
    call("adb install " + apk_path)


def main(options, args) :
    print options.input
    if options.input == None or options.output == None :
        print "dynamic_analysis.py -i <inputfile> -o <outputfolder>"
        sys.exit(2)
    else :
        static_analysis_file_path = options.output + "/" + hashfile(options.input) + "_static.json"

        apk_package          = ""
        apk_main_activity    = ""
        static_analysis_data = []
        
        if os.path.isfile(static_analysis_file_path) :
            print "\tstatic analysis found."
            fh                   = open(static_analysis_file_path)
            static_analysis_data = json.load(fh)

            apk_package          = static_analysis_data.get("package", None)
            apk_main_activity    = static_analysis_data.get("mainActivity", None)

            fh.close()
        else :
            print "\tstatic analysis NOT found."

            command      = "aapt dump badging " + options.input + " | awk -F\" \" '/package/ {print $2}' | awk -F\"'\" '/name=/ {print $2}'"
            apk_package  = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=None, shell=True).communicate()[0].rstrip()

            command           = "aapt dump badging " + options.input + " | awk -F\" \" '/launchable activity/ {print $3}' | awk -F\"'\" '/name=/ {print $2}'"
            apk_main_activity = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=None, shell=True).communicate()[0].rstrip()

        print "\tpackage:\t" + apk_package
        print "\tmain activity:\t" + apk_main_activity

        clean_state()
        start_vm()
        connect_adb()
        install_apk(options.input)
        stop_vm()


if __name__ == "__main__" :
    parser = OptionParser()
    parser.add_option("-i", "--input", dest="input", help="path to the APK file which shoud be analysed.")
    parser.add_option("-o", "--output", dest="output", help="folder to write the analysis result as json.")
    (options, args) = parser.parse_args()

    sys.argv[:] = args
    main(options, args)
