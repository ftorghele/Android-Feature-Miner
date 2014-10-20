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

import sys, hashlib, time, requests, json, os, threading, weakref

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

def analyse_traffic_features() :
    global malware

    traffic_data       = db.traffic_features.find_one({"_id": hashfile(options.input)})
    time_multiplicator = (1 / traffic_data.get('durations')['all']) * 60

    tasks = [
        "responseCodes",
        "destinationPorts",
        "contentTypes"
    ]

    if traffic_data != None :
        for task in tasks :
            responseCodes = traffic_data.get(task)
            for x in responseCodes :
                myId = task + "_" + x
                entry = db.analysis_traffic_features.find_one({"_id": myId})
                if entry == None :
                    entry = {
                        '_id'               : myId,
                        'inMalwareCount'    : 1 if malware else 0,
                        'inBenignCount'     : 0 if malware else 1,
                        'maxValue'          : responseCodes[x] * time_multiplicator,
                        'minValue'          : responseCodes[x] * time_multiplicator,
                    }
                    db.analysis_traffic_features.find_and_modify({'_id':myId}, entry, upsert=True)
                else :
                    if malware :
                        entry['inMalwareCount'] += 1
                    else :
                        entry['inBenignCount'] += 1

                    if entry['maxValue'] < responseCodes[x] * time_multiplicator :
                        entry['maxValue'] = responseCodes[x] * time_multiplicator
                    if entry['minValue'] > responseCodes[x] * time_multiplicator :
                        entry['minValue'] = responseCodes[x] * time_multiplicator

                    db.analysis_traffic_features.find_and_modify({'_id':myId}, entry)


def main(options, args) :
    global traffic_data

    if options.input == None or options.output == None :
        print "build_database_prepare.py -i <inputfile> -o <outputfolder>"
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



if __name__ == "__main__" :
    parser = OptionParser()
    parser.add_option("-i", "--input", dest="input", help="path to the APK file which shoud be analysed.")
    parser.add_option("-o", "--output", dest="output", help="folder to store pulled files.")
    (options, args) = parser.parse_args()

    sys.argv[:] = args
    main(options, args)