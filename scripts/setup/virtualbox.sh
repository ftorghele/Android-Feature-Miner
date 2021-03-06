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

printInfo "Installing VirtualBox.."

echo "deb http://download.virtualbox.org/virtualbox/debian wheezy contrib" | sudo tee /etc/apt/sources.list.d/virtualbox.list > /dev/null
wget -q http://download.virtualbox.org/virtualbox/debian/oracle_vbox.asc -O- | sudo apt-key add -
sudo apt-get update
sudo apt-get install --yes         \
  virtualbox-4.2                   \
  dkms                             \
  
# Add user to group	
usermod -a -G vboxusers $(whoami)
	
# Get installed VirtualBox version
VER=$(vboxmanage --version)
VER=${VER%%r*}
 
# Install extension pack
wget -O $DIR/../tools/Oracle_VM_VirtualBox_Extension_Pack-$VER.vbox-extpack http://download.virtualbox.org/virtualbox/$VER/Oracle_VM_VirtualBox_Extension_Pack-$VER.vbox-extpack
vboxmanage extpack install $DIR/../tools/Oracle_VM_VirtualBox_Extension_Pack-$VER.vbox-extpack --replace
rm -rf $DIR/../tools/Oracle_VM_VirtualBox_Extension_Pack-$VER.vbox-extpack

printInfo "Finished installing Virtualbox!"

