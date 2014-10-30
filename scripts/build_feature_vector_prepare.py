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

import sys, hashlib, time, requests, json, os, re

from optparse import OptionParser
from pymongo import MongoClient

client   = MongoClient('localhost', 6662)
db       = client.androsom
filehash = None

malware  = False

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

def set_malware_label() :
    global malware
    vt_metadata = db.virustotal_features.find_one({"sha1": hashfile(options.input)})
    if vt_metadata.get('positives') != 0 :
        malware = True

def analyse_dynamic_features() :
    dynamic_data    = db.dynamic_features.find_one({"_id": hashfile(options.input)})
    time_multiplier = (1 / dynamic_data.get('durations')['all']) * 120

    tasks = [
        "methodCalls",
    ]
    upsert_feature_array("dynamic", dynamic_data, ["methodCalls"], time_multiplier)

    tasks = [
        "accessedFiles",
        "openedFiles",
        "chmodedFiles",
    ]
    for task in tasks :
        results = dynamic_data.get(task)
        for x in results :
            match = re.search('([^\/]*)$', x)
            if match != None :
                id_part  = match.group(1)
            upsert_feature("dynamic", results.get(x, 0), id_part, task, time_multiplier)

def analyse_static_features() :
    static_data = db.static_features.find_one({"_id": hashfile(options.input)})

    tasks = [
        "isCryptoCode",
        "isDynamicCode",
        "isNativeCode",
        "isAsciiObfuscation",
        "isReflectionCode",
        "maxSdkVersion",
        "minSdkVersion",
        "targetSdkVersion",
        "androidVersion"
    ]
    for task in tasks :
        x = static_data.get(task)
        upsert_simple_feature("static", x, task)

    tasks = [
        "nativeMethodCount",
        "reflectionCount"
    ]
    for task in tasks :
        upsert_simple_feature("static", None, task)

    tasks = [
        "activities",
        "providers",
        "receivers",
        "services",
        "permissions",
        "libraries"
    ]
    for task in tasks :
        results = static_data.get(task)
        for x in results :
            match = re.search('\.([^\.]*)$', x)
            if match != None :
                x  = match.group(1)
            upsert_simple_feature("static", x, task)


    libraries = static_data.get("libraries")
    for library in libraries :
        library = library.replace(".", "_")
        upsert_simple_feature("static", library, "libraries")

    actualPermissions = static_data.get("actualPermissions")
    for permission in actualPermissions :
        upsert_signature_feature("static", actualPermissions[permission], permission)

    externalMethodCalls = static_data.get("externalMethodCalls")
    upsert_signature_feature("static", externalMethodCalls, "externalMethodCalls")

    #internalMethodCalls = static_data.get("internalMethodCalls")
    #upsert_signature_feature("static", internalMethodCalls, "internalMethodCalls")

def upsert_signature_feature(prefix, data, task) :
    if data != None :
        for namespace in data :
            for classname in data.get(namespace) :
                class_part = classname[1:] + "->"
                for methodname in data.get(namespace).get(classname) :
                    signature = class_part + methodname
                    signature = signature.replace(";", "")
                    count = 0
                    for call in data.get(namespace).get(classname).get(methodname) :
                        count += data.get(namespace).get(classname).get(methodname).get(call)

                    upsert_feature(prefix, count, signature, task, 1)

def analyse_traffic_features() :
    traffic_data    = db.traffic_features.find_one({"_id": hashfile(options.input)})
    time_multiplier = (1 / traffic_data.get('durations')['all']) * 120
    tasks = [
        "responseCodes",
        "accessedIps",
        "accessedHostnames",
        "destinationPorts",
        "contentTypes"
    ]
    upsert_feature_array("traffic", traffic_data, tasks, time_multiplier)

def upsert_simple_feature(prefix, x, task) :
    global malware
    myId = prefix + "_" + task + "__" + str(x)
    entry = db[options.collection].find_one({"_id": myId})
    if entry == None :
        entry = {
            '_id'               : myId,
            'inMalwareCount'    : 1 if malware else 0,
            'inBenignCount'     : 0 if malware else 1,
        }
        db[options.collection].find_and_modify({'_id':myId}, entry, upsert=True)
    else :
        if malware :
            entry['inMalwareCount'] += 1
        else :
            entry['inBenignCount'] += 1

        db[options.collection].find_and_modify({'_id':myId}, entry)

def upsert_feature_array(prefix, data, tasks, multiplier) :
    if data != None :
        for task in tasks :
            results = data.get(task)
            for x in results :
                upsert_feature(prefix, results.get(x, 0), x, task, multiplier)

def upsert_feature(prefix, data, x, task, multiplier) :
    global malware
    myId = prefix
    if task != None :
        myId += "_" + task 
    if x != None :
        myId += "__" + str(x)
    
    entry = db[options.collection].find_one({"_id": myId})
    if entry == None :
        entry = {
            '_id'               : myId,
            'inMalwareCount'    : 1 if malware else 0,
            'inBenignCount'     : 0 if malware else 1,
            'maxValue'          : data * multiplier,
            'minValue'          : data * multiplier,
        }
        db[options.collection].find_and_modify({'_id':myId}, entry, upsert=True)
    else :
        if malware :
            entry['inMalwareCount'] += 1
        else :
            entry['inBenignCount'] += 1

        if entry['maxValue'] < data * multiplier :
            entry['maxValue'] = data * multiplier
        if entry['minValue'] > data * multiplier :
            entry['minValue'] = data * multiplier

        db[options.collection].find_and_modify({'_id':myId}, entry)

def main(options, args) :
    if options.input == None or options.output == None :
        print "build_feature_vector_prepare.py -i <inputfile> -o <outputfolder>"
        sys.exit(2)
    elif db.dynamic_features.find({"_id": hashfile(options.input), "valid": True}).count() == 0 :
        print "no valid dynamic analysis found.. skipping.."
        sys.exit(0)
    elif db.traffic_features.find({"_id": hashfile(options.input), "valid": True}).count() == 0 :
        print "no valid traffic analysis found.. skipping.."
        sys.exit(0)
    elif db.virustotal_features.find({"sha1": hashfile(options.input)}).count() == 0 :
        print "virus total metadata not found.. skipping.."
        sys.exit(0)
    elif db.virustotal_features.find({ "$or": [ { "positives": 0 }, { "positives": { "$gte": 35 } } ], "sha1": hashfile(options.input) }).count() == 0 :
        print "not clear enough benign or malicious.. skipping.."
        sys.exit(0)
    elif db.static_features.find({"_id": hashfile(options.input)}).count() == 0 :
        print "no valid static analysis found.. skipping.."
        sys.exit(0)
    else :
        set_malware_label()
        analyse_traffic_features()
        analyse_dynamic_features()
        analyse_static_features()

if __name__ == "__main__" :
    parser = OptionParser()
    parser.add_option("-i", "--input", dest="input", help="path to the APK file which shoud be analysed.")
    parser.add_option("-o", "--output", dest="output", help="folder to store pulled files.")
    parser.add_option("-c", "--collection", dest="collection", default="features", help="database collection to store data.")
    (options, args) = parser.parse_args()

    sys.argv[:] = args
    main(options, args)

