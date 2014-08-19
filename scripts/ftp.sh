#!/bin/sh
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
if [ $1 ] && [ -d $2 ]
then

  if [ "$1" = "start" ]
  then
    nohup python -m pyftpdlib -i localhost -p 6661 -w -d $2 >/dev/null 2> $2/ftp.log &
    echo $! > $2/ftp.pid
    echo "Started ftp server."
    exit 1
  elif [ "$1" = "stop" ]
  then
    PID=`cat $2/ftp.pid`
    kill $PID
    if [ $? -eq 0 ]
    then
      rm -f $2/ftp.pid
    fi
    echo "Stopped ftp server."
    exit 1
  else
    echo "Usage: $0 <start|stop> <file root>"
    exit 0
  fi

else
  echo "Usage: $0 <start|stop> <file root>"
  exit 0
fi
