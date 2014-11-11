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

import sys, re

from optparse import OptionParser
from pymongo import MongoClient

client      = MongoClient('localhost', 6662)
db          = client.androsom


def main(options, args) :
    if options.type == None or options.filter == None :
        print "check_filter.py -t <type> -f <filter>"
        sys.exit(2)
    else :

        count_filtered = db.features.find({ "$and": [ { "_id": { '$regex': '^' + re.escape(options.type) } }, { "$or": [ { "inMalwareCount": { "$gte": int(options.filter) } }, { "inBenignCount": { "$gte": int(options.filter) } } ] } ] }).count()
        count_all      = db.features.find({ "_id": { '$regex': '^' + re.escape(options.type) } }).count()
        percentage     = (100.00/count_all)*count_filtered
        print options.type + ": " + str(count_filtered) + " of " + str(count_all) + " (" + str(percentage) + "%) \n"

if __name__ == "__main__" :
    parser = OptionParser()
    parser.add_option("-t", "--type", dest="type", help="the feature type.")
    parser.add_option("-f", "--filter", dest="filter", help="the filter.")
    (options, args) = parser.parse_args()

    sys.argv[:] = args
    main(options, args)