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

printInfo "Taking 'cleanstate' snapshot"

VBoxManage snapshot AndroidVM take cleanstate --live
sleep 10
VBoxManage controlvm AndroidVM poweroff
VBoxManage snapshot AndroidVM restore cleanstate

printInfo "Finished taking 'cleanstate' snapshot! Powering down VM.."

