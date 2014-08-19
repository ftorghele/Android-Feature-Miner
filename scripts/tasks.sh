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

#LOG_DIR="/data/local/features";
LOG_DIR="/sdcard/features";

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

# prepare log directory
function fnPrepare() {
  if [ -e $LOG_DIR ]
  then
    rm -rf "$LOG_DIR/*"
  else
    mkdir $LOG_DIR
  fi
}

# tcpdump related tasks
function fnTcpdump() {
  if [ "$1" = "start" ]
  then
    nohup tcpdump -s 65535 -nn -w "$LOG_DIR/tcpdump.pcap" not port 5555 > "$LOG_DIR/tcpdump.out" & 
    echo "Started tcpdump."
  elif [ "$1" = "stop" ]
  then
    TCPDUMP_PID=`pgrep tcpdump`
    kill -INT $TCPDUMP_PID
    wait $TCPDUMP_PID
    echo "Stopped tcpdump with PID \"$TCPDUMP_PID\"."
  else
    die "Usage: $0 tcpdump <start|stop>"
  fi
}

# compress data for faster transfer
function fnCompressAndTransfer() {
  cd $LOG_DIR && tar -zcvf ../features.tar.gz . 
  ftpput -v -P 6661 10.0.2.2 ../features.tar.gz
}

# start the monkey runner with strace
function fnMonkey() {
if [ $1 ] && [ $2 ]
  then
    echo "Starting monkey runner on \"$1\" with $2 steps."
    nohup monkey --throttle 100 -p $1 -v $2 > "$LOG_DIR/monkey.out" &
    MONKEY_PID=$!
  
    echo "Waiting to start strace on \"$1\"."
    while true
    do 
      if pgrep $1 | egrep -q '^[0-9]+$';
      then
        APP_PID=`pgrep $1`
        kill -SIGSTOP $MONKEY_PID
        kill -SIGSTOP $APP_PID
        nohup strace -p$APP_PID -t -tt -f -ff -o"$LOG_DIR/stracelog" > "$LOG_DIR/strace.out" &
        kill -SIGCONT $APP_PID
        kill -SIGCONT $MONKEY_PID
        break;
      fi
    done
    echo "Started strace on \"$1\"."
    wait $MONKEY_PID
    killall strace
  else  
    die "Usage: $0 monkey <process name> <number of steps>"
  fi
}

# run one of the tasks
if [ "$1" = "tcpdump" ]
then
  fnTcpdump $2
elif [ "$1" = "monkey" ]
then
  fnMonkey $2 $3
elif [ "$1" = "transfer" ]
then
  fnCompressAndTransfer
elif [ "$1" = "prepare" ]
then
  fnPrepare
else
  die "Usage: $0 <prepare|monkey|tcpdump|transfer>"
fi