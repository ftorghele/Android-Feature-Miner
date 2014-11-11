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

import sys, hashlib, os, re, shutil

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

def write_dataset(analysis_type, analysis_filter) :
    dataset   = open(options.output + "/" + analysis_type + "_X", 'w')
    variables = open(options.output + "/" + analysis_type + "_label_variable", 'w')

    query = { "$and": [ { "_id": { '$regex': '^' + re.escape(analysis_type) } }, { "$or": [ { "inMalwareCount": { "$gte": int(analysis_filter) } }, { "inBenignCount": { "$gte": int(analysis_filter) } } ] } ] }
    for feature in db.features.find(query).sort("_id", 1) :
        variables.write(feature.get('_id') + "\n")

    list_dir = []
    list_dir = os.listdir(current_dir + "/../tmp/")
    for file in list_dir :
        if file.endswith(analysis_type + "_features") :
            with open(current_dir + "/../tmp/"+ file, 'r') as f:
                dataset.write(f.readline() + "\n")

    dataset.close()
    variables.close()

def write_classes_and_sample_labels() :
    classes   = open(options.output + "/class", 'w')
    samples   = open(options.output + "/label_sample", 'w')

    list_dir = []
    list_dir = os.listdir(current_dir + "/../tmp/")
    for file in list_dir :
        if file.endswith("static_features") :
            sha1 = file.replace(".static_features", "")
            samples.write(sha1 + "\n")

            metadata = db.virustotal_features.find_one({"sha1": sha1})

            if metadata.get('positives') == 0 :
                classes.write("1\n") # Benign
            else :
                classes.write("2\n") # Malware

    classes.close()
    samples.close()

def build_full_dataset() :
    dataset  = open(options.output + "/full_X", 'w')

    list_dir = []
    list_dir = os.listdir(current_dir + "/../tmp/")
    for file in list_dir :
        if file.endswith("static_features") :

            sha1 = file.replace(".static_features", "")
            feature_vector = ""

            with open(current_dir + "/../tmp/" + sha1 + ".static_features", 'r') as f:
                feature_vector += (f.readline().strip() + ", ")
            with open(current_dir + "/../tmp/" + sha1 + ".dynamic_features", 'r') as f:
                feature_vector += (f.readline().strip() + ", ")
            with open(current_dir + "/../tmp/" + sha1 + ".traffic_features", 'r') as f:
                feature_vector += f.readline().strip()

            dataset.write(feature_vector + "\n")
    
    dataset.close()
    
def build_full_variabls_labels() :
    variables = open(options.output + "/full_label_variable", 'wb')
    shutil.copyfileobj(open(options.output + "/static_label_variable",'rb'), variables)
    shutil.copyfileobj(open(options.output + "/dynamic_label_variable",'rb'), variables)
    shutil.copyfileobj(open(options.output + "/traffic_label_variable",'rb'), variables)
    variables.close()

def main(options, args) :
    feature_count = count_files(current_dir + "/../tmp/", "features") / 3

    if options.output == None :
        print "build_datasets.py -o <outputfolder> -s <staticFilter> -d <dynamicFilter> -t <trafficFilter>"
        sys.exit(2)
    elif feature_count == 0 :
        print "no feature vectors found in tmp folder.."
        sys.exit(0)
    else :
        print "found " + str(feature_count) + " features.."

        write_dataset("static", options.staticFilter)
        write_dataset("dynamic", options.dynamicFilter)
        write_dataset("traffic", options.trafficFilter)
        write_classes_and_sample_labels()
        build_full_dataset()
        build_full_variabls_labels()

if __name__ == "__main__" :
    parser = OptionParser()
    parser.add_option("-o", "--output", dest="output", help="folder to store pulled files.")
    parser.add_option("-s", "--staticFilter", dest="staticFilter", default=50, help="minimum count of samples with a certain static feature.")
    parser.add_option("-d", "--dynamicFilter", dest="dynamicFilter", default=50, help="minimum count of samples with a certain dynamic feature.")
    parser.add_option("-t", "--trafficFilter", dest="trafficFilter", default=50, help="minimum count of samples with a certain traffic feature.")
    (options, args) = parser.parse_args()

    sys.argv[:] = args
    main(options, args)