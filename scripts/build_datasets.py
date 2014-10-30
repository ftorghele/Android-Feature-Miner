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

def count_files(path,extension):
    list_dir = []
    list_dir = os.listdir(path)
    count = 0
    for file in list_dir:
        if file.endswith(extension):
            count += 1
    return count

def main(options, args) :
    feature_count = count_files(current_dir + "/../tmp/", "features")

    if options.output == None :
        print "build_datasets.py -o <outputfolder>"
        sys.exit(2)
    elif feature_count == 0 :
        print "no feature vectors found in tmp folder.."
        sys.exit(0)
    else :
        print "found " + str(feature_count) + " features.."

        dataset              = open(options.output + "/X", 'w')
        classes              = open(options.output + "/class", 'w')
        samples              = open(options.output + "/label_sample", 'w')
        features             = open(options.output + "/label_variable", 'w')

        for feature in db.features.find({ "$or": [ { "inMalwareCount": { "$gte": 50 } }, { "inBenignCount": { "$gte": 50 } } ] }).sort("_id", 1) :
            features.write(feature.get('_id') + "\n")

        #labels_malware_ids   = open(options.output + "/labels_malware_ids.androsom", 'w')
        #labels_malware_names = open(options.output + "/labels_malware_names.androsom", 'w')

        sample_labels = ["benign"]

        list_dir = []
        list_dir = os.listdir(current_dir + "/../tmp/")
        for file in list_dir :
            if file.endswith("features") :
                with open(current_dir + "/../tmp/"+ file, 'r') as f:
                    dataset.write(f.readline())

                sample_name = file.replace(".features", "")

                samples.write(sample_name + "\n")

                metadata = db.virustotal_features.find_one({"sha1": sample_name})

                if metadata.get('positives') == 0 :
                    classes.write("1\n")
                    #labels_malware_ids.write("0\n")
                else :
                    classes.write("2\n")
                    '''
                    scans = metadata.get('scans')
                    sample_label = "???"
                    for vendor in ["Symantec", "Avast", "BitDefender", "F-Secure", "AVG"] :
                        vendor = scans.get(vendor)
                        if vendor != None :
                            result = vendor.get('result')
                            if result != None :
                                sample_label = result
                                break

                    if sample_label not in sample_labels :
                        sample_labels.append(sample_label)

                    labels_malware_ids.write(str(sample_labels.index(sample_label)) + "\n")

        for i in sample_labels :
            labels_malware_names.write(str(sample_labels.index(i)) + "\t" + str(i) + "\n")
        '''
        dataset.close()
        classes.close()
        samples.close()
        features.close()

        #labels_malware_ids.close()
        #labels_malware_names.close()

if __name__ == "__main__" :
    parser = OptionParser()
    parser.add_option("-o", "--output", dest="output", help="folder to store pulled files.")
    (options, args) = parser.parse_args()

    sys.argv[:] = args
    main(options, args)