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

printInfo "Installing dependencies.."
sudo apt-get update
sudo apt-get install --yes \
  ia32-libs                \

printInfo "Download and install apktool-install.."
if [ ! -f /usr/local/bin/aapt ]; then 
	wget http://android-apktool.googlecode.com/files/apktool-install-linux-r04-brut1.tar.bz2 && tar --wildcards --no-anchored -xjvf apktool-install-linux-r04-brut1.tar.bz2; sudo -v; sudo mv aapt /usr/local/bin/; sudo -v; sudo mv apktool /usr/local/bin/; sudo -v; sudo chmod 777 /usr/local/bin/aapt; sudo -v; sudo chmod 777 /usr/local/bin/apktool; rm apktool-install-linux-r04-brut1.tar.bz2; rm -rf apktool-install-linux-r04-brut1/;
else
    echo "apktool-install already installed to /usr/local/bin.  Skipping."
fi

printInfo "Download and install apktool.."
if [ ! -f "/usr/local/bin/apktool.jar" ]; then 
	wget http://android-apktool.googlecode.com/files/apktool1.4.3.tar.bz2 && tar --wildcards --no-anchored -xjvf apktool1.4.3.tar.bz2; sudo -v; sudo mv apktool.jar /usr/local/bin/; sudo -v; sudo chmod 777 /usr/local/bin/apktool.jar; rm apktool1.4.3.tar.bz2; rm -rf apktool1.4.3/;
else
    echo "apktool already installed to /usr/local/bin.  Skipping."
fi

printInfo "Download and install the Android SDK.."
if [ ! -d "/usr/local/android-sdk" ]; then
for a in $( wget -qO- http://developer.android.com/sdk/index.html | egrep -o "http://dl.google.com[^\"']*linux.tgz" ); do
wget $a && tar --wildcards --no-anchored -xvzf android-sdk_*-linux.tgz; sudo -v; sudo mv android-sdk-linux /usr/local/android-sdk; sudo -v; sudo chmod 777 -R /usr/local/android-sdk; rm android-sdk_*-linux.tgz;
done
else
echo "Android SDK already installed to /usr/local/android-sdk. Skipping."
fi

printInfo "Download and install the Android NDK.."
if [ ! -d "/usr/local/android-ndk" ]; then 
	for b in $(  wget -qO- http://developer.android.com/sdk/ndk/index.html | egrep -o "http://dl.google.com[^\"']*linux-x86.tar.bz2"
 ); do wget $b && tar --wildcards --no-anchored -xjvf android-ndk-*-linux-x86.tar.bz2; sudo -v; sudo mv android-ndk-*/ /usr/local/android-ndk; sudo -v; sudo chmod 777 -R /usr/local/android-ndk; rm android-ndk-*-linux-x86.tar.bz2;
	done
else
    echo "Android NDK already installed to /usr/local/android-ndk.  Skipping."
fi

printInfo "Create Symlink for Dalvik Debug Monitor Server (DDMS).."
if [ -f /bin/ddms ] 
then
    sudo -v; sudo rm /bin/ddms; sudo -v; sudo ln -s /usr/local/android-sdk/tools/ddms /bin/ddms
else
    sudo -v; sudo ln -s /usr/local/android-sdk/tools/ddms /bin/ddms
fi

printInfo "Create a symlink for Android Debug Bridge (adb)"
if [ -f /bin/adb ];
then
    sudo -v; sudo rm /bin/adb; sudo -v; sudo ln -s /usr/local/android-sdk/platform-tools/adb /bin/adb
else
    sudo -v; sudo ln -s /usr/local/android-sdk/platform-tools/adb /bin/adb
fi

printInfo "Installing adb.."
if [ ! -f "/usr/local/android-sdk/platform-tools/adb" ];
then  
	mkdir $HOME/.android; touch $HOME/.android/androidtool.cfg; echo "sdkman.force.http=true" > $HOME/.android/androidtool.cfg; nohup /usr/local/android-sdk/tools/android update sdk > /dev/null 2>&1
else
echo "Android Debug Bridge already detected."
fi

printInfo "Finished installing Android dependencies!"

