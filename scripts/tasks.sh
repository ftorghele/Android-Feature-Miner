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
function fnTransfer() {
  cd $LOG_DIR && ls | tr '\r' ' ' | xargs -n1 ftpput -v -P 6661 10.0.2.2
}

# start the monkey runner with strace
function fnMonkeyZygote() {
  if [ $1 ] && [ $2 ] && [ $3 ]
  then
    echo "Starting strace on zygote."
    ZYGOTE_PID=`pgrep zygote`
    nohup strace -p$ZYGOTE_PID -t -tt -f -ff -s256 -o"$LOG_DIR/strace$3.log" > "$LOG_DIR/strace$3.out" &
    STRACE_PID=$!

    echo "Starting monkey runner with $2 steps."
    nohup monkey --throttle 250 --kill-process-after-error -p $1 -v $2 > "$LOG_DIR/monkey$3.out" &
    MONKEY_PID=$!
    wait $MONKEY_PID

    # concatenate logs if necessary
    cd $LOG_DIR
    if (ls ./strace$3.log.* >/dev/null)
    then
      cat ./strace$3.log.* >> ./strace$3.log
      rm ./strace$3.log.*
    fi
  else  
    die "Usage: $0 monkey <process name> <number of steps> <log suffix>"
  fi
}
function fnMonkey() {
   if [ $1 ] && [ $2 ] && [ $3 ]
   then
     echo "Starting monkey runner with $2 steps."
     nohup monkey --throttle 250 --kill-process-after-error -p $1 -v $2 > "$LOG_DIR/monkey$3.out" &
     MONKEY_PID=$!
   
     echo "Waiting to start strace on \"$1\"."
     while true
     do 
       if pgrep $1 | egrep -q '^[0-9]+$';
       then
         APP_PID=`pgrep $1`
         nohup strace -p$APP_PID -t -tt -f -ff -s256 -o"$LOG_DIR/strace$3.log" > "$LOG_DIR/strace$3.out" &
         break;
       fi
     done
     echo "Started strace on \"$1\"."
     wait $MONKEY_PID

     # concatenate logs if necessary
     cd $LOG_DIR
     if (ls ./strace$3.log.* >/dev/null)
     then
       cat ./strace$3.log.* >> ./strace$3.log
       rm ./strace$3.log.*
     fi
   else  
     die "Usage: $0 monkey <process name> <number of steps> <log suffix>"
   fi
 }

function fnClearStrace() {
  if [ $1 ]
  then
    echo "Clearing strace logs with suffix $1"
    cd $LOG_DIR
    rm -f ./strace$3.*
  else  
    die "Usage: $0 clear_strace <log suffix>"
  fi
}

# run one of the tasks
if [ "$1" = "tcpdump" ]
then
  fnTcpdump $2
elif [ "$1" = "monkey" ]
then
  fnMonkey $2 $3 $4
elif [ "$1" = "monkey_zygote" ]
then
  fnMonkeyZygote $2 $3 $4
elif [ "$1" = "transfer" ]
then
  fnTransfer
elif [ "$1" = "prepare" ]
then
  fnPrepare
elif [ "$1" = "clear_strace" ]
then
  fnClearStrace $2
else
  die "Usage: $0 <prepare|monkey|monkey_zygote|tcpdump|transfer|clear_strace>"
fi