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

import sys, hashlib, time, requests, json, os

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

def request_report(sha1) :
    print "requesting data for: " + sha1
    params   = { 'apikey': options.key, 'resource': sha1 }
    response = requests.get('https://www.virustotal.com/vtapi/v2/file/report', params=params)
    response.raise_for_status()

    data          = json.loads(response.content)
    response_code = data.get('response_code')

    if response_code == 0 :
        # not found
        upload_file(options.input)
    elif response_code == 1 :
        # found, insert into db
        db.virustotal_features.insert(data)
    elif response_code == -2 :
        # still queued for analysis
        print sha1 + ": still in queue, check back later."
    else :
        print "unknown response code " + response_code + " for " + options.input

def upload_file(path) :
    sha1     = hashfile(options.input)
    params   = {'apikey': options.key}
    files    = {'file': (os.path.basename(path), open(path, 'rb'))}
    print sha1 + " uploading.."

    if os.path.getsize(path) >= 33554432 : # 32MB
        if options.delay >= 25000 :        # public api: max 4 per minute 
            print sha1 + ": is to big for upload via public api.. skipping.."
            sys.exit(0)

        # obtaining the upload URL
        response      = requests.get('https://www.virustotal.com/vtapi/v2/file/scan/upload_url', params=params)
        json_response = response.json()
        upload_url    = json_response.get('upload_url')
        # submitting the file to the upload URL
        response      = requests.post(upload_url, files=files)
        json_response = response.json()
        print sha1 + ": " + json_response.get('verbose_msg')
    else :
        time.sleep(options.delay / 1000)
        response      = requests.post('https://www.virustotal.com/vtapi/v2/file/scan', files=files, params=params)
        json_response = response.json()
        print sha1 + ": " + json_response.get('verbose_msg')
    

def main(options, args) :
    if options.input == None or options.key == None or options.delay == None :
        print "virus_total.py -i <input file path> -k <api key> -d <delay in milliseconds>"
        sys.exit(2)
    elif db.static_features.find({"_id": hashfile(options.input), 'validApk': False}, limit=1).count() > 0 :
        print "Not a valid APK.. skipping.. "
        sys.exit(0)
    elif db.virustotal_features.find({"sha1": hashfile(options.input)}).count() > 0 :
        print "dynamic analysis found.. skipping.."
        sys.exit(0)
    else :
        request_report(hashfile(options.input))

if __name__ == "__main__" :
    parser = OptionParser()
    parser.add_option("-i", "--input", dest="input", help="path to the APK file which shoud be analysed.")
    parser.add_option("-k", "--key", dest="key", help="your virus total api key.")
    parser.add_option("-d", "--delay", dest="delay", metavar="NUMBER", type="int", help="delay between api calls an milliseconds.")
    (options, args) = parser.parse_args()

    sys.argv[:] = args
    main(options, args)
