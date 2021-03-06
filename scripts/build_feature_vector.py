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

import sys, hashlib, time, requests, json, os, re, subprocess

from optparse import OptionParser
from pymongo import MongoClient

current_dir = os.path.dirname(sys.argv[0])

client      = MongoClient('localhost', 6662)
db          = client.androsom
filehash    = None

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

def build_vector(analysis_type, analysis_filter) :
    filepath = current_dir + '/../tmp/' + hashfile(options.input) + '.' + analysis_type + '_features'

    query = { "$and": [ { "_id": { '$regex': '^' + re.escape(analysis_type) } }, { "$or": [ { "inMalwareCount": { "$gte": int(analysis_filter) } }, { "inBenignCount": { "$gte": int(analysis_filter) } } ] } ] }
    count = 0

    f = open(filepath, 'wb+')
    for feature in db.features.find(query).sort("_id", 1) :
        sample = db["features_" + hashfile(options.input)].find_one({"_id": feature.get('_id')})
        count += 1
        if sample != None :
            maxValue = feature.get('maxValue', None)
            if maxValue != None :
                value = (1 / maxValue) * sample.get('maxValue')
                f.write("%s, " % str(value))
            else :
                f.write("1, ")
        else :
            f.write("0, ")
    if count != 0 :
        f.seek(-2, os.SEEK_END)
        f.truncate() 
    f.close()

def main(options, args) :
    if options.input == None or options.output == None :
        print "build_feature_vector.py -i <inputfile> -o <outputfolder> -s <staticFilter> -d <dynamicFilter> -t <trafficFilter>"
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
        db.drop_collection('features_' + hashfile(options.input))
        cmd = [ current_dir + "/build_feature_vector_prepare.py", "-i", options.input, "-o", options.output, "-c", "features_" + hashfile(options.input) ]
        subprocess.call(cmd)

        build_vector("static", options.staticFilter)
        build_vector("dynamic", options.dynamicFilter)
        build_vector("traffic", options.trafficFilter)
        
        db.drop_collection('features_' + hashfile(options.input))

if __name__ == "__main__" :
    parser = OptionParser()
    parser.add_option("-i", "--input", dest="input", help="path to the APK file which shoud be analysed.")
    parser.add_option("-o", "--output", dest="output", help="folder to store pulled files.")
    parser.add_option("-s", "--staticFilter", dest="staticFilter", default=50, help="minimum count of samples with a certain static feature.")
    parser.add_option("-d", "--dynamicFilter", dest="dynamicFilter", default=50, help="minimum count of samples with a certain dynamic feature.")
    parser.add_option("-t", "--trafficFilter", dest="trafficFilter", default=50, help="minimum count of samples with a certain traffic feature.")
    (options, args) = parser.parse_args()

    sys.argv[:] = args
    main(options, args)