#!/bin/bash
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

DIR="$(dirname "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")")"

# Let the script exit with a optional message and exit code.
function die { 
  if [ $# -eq 2 ]
  then
    echo $1; exit $2;
  elif [ $# -eq 1 ]
  then
    echo $1; exit 0;
  else
    exit 0;
  fi
}

printHeader() {
  clear
  cat<<EOF
################################################################################
#               _              _          ____   ___  __  __                   #
#              / \   _ __   __| |_ __ ___/ ___| / _ \|  \/  |                  #
#             / _ \ | '_ \ / _  | '__/ _ \___ \| | | | |\/| |                  #
#            / ___ \| | | | (_| | | | (_) |__) | |_| | |  | |                  #
#           /_/   \_\_| |_|\__,_|_|  \___/____/ \___/|_|  |_| v 0.0.1          #
#                                                                              #
################################################################################

EOF
}

printInfo() {
echo
echo "-------------------------------------------------------------------------------"
echo "### $*"
echo "-------------------------------------------------------------------------------"
}

printHeader
[[ "$UID" -eq "0" ]] && die "Do not run this script as root."

# ----------------------------------------------------------------------------------

printInfo "Installing various dependencies.."

sudo apt-get update
sudo apt-get install --yes \
  gawk                     \
  tshark                   \
  python                   \
  python-pip               \

sudo pip install pyftpdlib
sudo pip install requests

rm -rf $DIR/../tools/pcapfix*
cd $DIR/../tools
wget https://www.dropbox.com/s/6ui3du5b8ipbc5j/pcapfix-1.0.2.tar.gz
tar -zxf pcapfix-1.0.2.tar.gz
cd $DIR/../tools/pcapfix-1.0.2
make && sudo make install
rm -rf ../pcapfix-1.0.2.tar.gz ../pcapfix-1.0.2

rm -rf $DIR/../tools/mongodb
cd $DIR/../tools
wget http://downloads.mongodb.org/linux/mongodb-linux-x86_64-2.6.4.tgz
tar -zxf mongodb-linux-x86_64-2.6.4.tgz
mv mongodb-linux-x86_64-2.6.4 mongodb
cd $DIR/../tools/mongodb
rm -rf ../mongodb-linux-x86_64-2.6.4.tgz

sudo pip install pymongo

printInfo "Finished installing dependencies!"

