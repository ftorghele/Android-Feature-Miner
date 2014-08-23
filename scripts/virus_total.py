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

import sys, hashlib, time

from optparse import OptionParser
from pymongo import MongoClient

client   = MongoClient('localhost', 6662)
db       = client.androsom
filehash = None

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

def main(options, args) :
    #print options.input

    if options.input == None :
        print "virus_total.py -i <inputfile>"
        sys.exit(2)
    elif db.static_features.find({"_id": hashfile(options.input), 'validApk': False}).count() == 1 :
        print "Not a valid APK.. skipping.. "
        sys.exit(0)
    else :
        print "valid APK"




if __name__ == "__main__" :
    parser = OptionParser()
    parser.add_option("-i", "--input", dest="input", help="path to the APK file which shoud be analysed.")
    parser.add_option("-o", "--output", dest="output", help="folder to write files if necessary.")
    (options, args) = parser.parse_args()

    sys.argv[:] = args
    main(options, args)
