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

printInfo "Installing AndroGuard.."

rm -rf $DIR/../tools/androguard

printInfo "Install development packages:"
sudo apt-get update
sudo apt-get install --yes \
  mercurial                \
  python                   \
  python-setuptools        \
  g++                      \

printInfo "Download Androguard's sources:"
hg clone https://androguard.googlecode.com/hg/ $DIR/../tools/androguard 

printInfo "Install requirements:"
sudo apt-get install --yes \
  python-dev               \
  python-bzutils           \
  libbz2-dev               \
  libmuparser-dev          \
  libsparsehash-dev        \
  python-ptrace            \
  python-pygments          \
  python-pydot             \
  graphviz                 \
  liblzma-dev              \
  libsnappy-dev            \
  zlib1g-dev               \

printInfo "Getting chilkat:"
cd $DIR/../tools/androguard
wget http://ftp.chilkatsoft.com/download/9.5.0.40/chilkat-9.5.0-python-3.4-x86_64-linux.tar.gz
tar -zxvf chilkat-9.5.0-python-3.4-x86_64-linux.tar.gz
mv ./chilkat-9.5.0-python-3.4-x86_64-linux/* ./
rm -rf chilkat-9.5.0-python-3.4-x86_64-linux chilkat-9.5.0-python-3.4-x86_64-linux.tar.gz

printInfo "Getting iPython:"
sudo easy_install ipython

printInfo "Getting pyFuzzy:"
cd $DIR/../tools/androguard
wget http://sourceforge.net/projects/pyfuzzy/files/latest/download?source=files -O pyfuzzy-0.1.0.tar.gz
tar xvfz pyfuzzy-0.1.0.tar.gz
rm -rf pyfuzzy-0.1.0.tar.gz
cd pyfuzzy-0.1.0
sudo python setup.py install

printInfo "Getting python-magic:"
cd $DIR/../tools/androguard
git clone git://github.com/ahupp/python-magic.git
cd python-magic
sudo python setup.py install 

printInfo "Build:"
cd $DIR/../tools/androguard && make

printInfo "Set Permissions to current user"
sudo chown -R `whoami`:`whoami` $DIR/../tools/androguard

printInfo "Finished installing Androguard!"

