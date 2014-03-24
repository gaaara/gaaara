#!/bin/sh
#############
###<Notes>###
#############
# This script depends on screen.
# For the stop function to work, you must set an
# explicit session directory using ABSOLUTE paths (no, ~ is not absolute) in your rtorrent.rc.
# If you typically just start rtorrent with just "rtorrent" on the
# command line, all you need to change is the "user" option.
# Attach to the screen session as your user with 
# "screen -dr rtorrent". Change "rtorrent" with srnname option.
# Licensed under the GPLv2 by lostnihilist: lostnihilist _at_ gmail _dot_ com
##############
###</Notes>###
##############

#######################
##Start Configuration##
#######################
# You can specify your configuration in a different file 
# (so that it is saved with upgrades, saved in your home directory,
# or whateve reason you want to)
# by commenting out/deleting the configuration lines and placing them
# in a text file (say /home/user/.rtorrent.init.conf) exactly as you would
# have written them here (you can leave the comments if you desire
# and then uncommenting the following line correcting the path/filename 
# for the one you used. note the space after the ".".
# . /etc/rtorrent.init.conf

#Do not put a space on either side of the equal signs e.g.
# user = user 
# will not work
# system user to run as
user=$2

# the system group to run as, not implemented, see d_start for beginning implementation
# group=`id -ng "$user"`

# the full path to the filename where you store your rtorrent configuration
config="`su $user -c 'echo ~/' `.rtorrent.rc"

# set of options to run with
options=""

# default directory for screen, needs to be an absolute path
base="`su $user -c 'echo ~/'`"

# name of screen session
srnname="rtorrent-$user"

# file to log to (makes for easier debugging if something goes wrong)
logfile="/var/log/rtorrentInit.log"
#######################
###END CONFIGURATION###
#######################
PATH=/usr/bin:/usr/local/bin:/usr/local/sbin:/sbin:/bin:/usr/sbin
DESC="rtorrent"
NAME=rtorrent
DAEMON=$NAME
SCRIPTNAME=/etc/init.d/$NAME

checkcnfg() {
    exists=0
    for i in `echo "$PATH" | tr ':' '\n'` ; do
        if [ -f $i/$NAME ] ; then
            exists=1
            break
        fi
    done
    if [ $exists -eq 0 ] ; then
        echo "cannot find rtorrent binary in PATH $PATH" | tee -a "$logfile" >&2
        exit 3
    fi
    if ! [ -r "${config}" ] ; then 
        echo "cannot find readable config ${config}. check that it is there and permissions are appropriate" | tee -a "$logfile" >&2
        exit 3 
    fi 
    session=`getsession "$config"` 
    if ! [ -d "${session}" ] ; then
        echo "cannot find readable session directory ${session} from config ${config}. check permissions" | tee -a "$logfile" >&2
        exit 3
    fi
}

d_start() {
    cd "${base}"
    running=$(ps -ef | grep "$srnname" | grep -v grep)

    if [ ! -z "$running" ];
    then    
        echo "$srnname is already running" >&2
        return
    else
  #stty stop undef && stty start undef
      su $user -c "screen -dmS ${srnname} rtorrent"
    fi
}

d_stop() {
    session=`getsession "$config"`
    if ! [ -s ${session}/rtorrent.lock ] ; then
        return
    fi
    #awk -F: '{print($2)}' |
    #pid=`cat ${session}/rtorrent.lock | sed "s/[^0-9]//g"`
    #if ps -ef | grep -sq ${pid}.*rtorrent ; then # make sure the pid doesn't belong to another process
    #    kill -s INT ${pid}
    #fi
    pid=`ps -ef | grep rtorrent-$user | grep -v grep | awk '{print $2}'`
    kill -9 ${pid}
    rm /home/$user/rtorrent/session/rtorrent.lock
}

getsession() { 
    session=`cat "$1" | grep "^[[:space:]]*session[[:space:]]*=" | sed "s/^[[:space:]]*session[[:space:]]*=[[:space:]]*//" `
    echo $session
}

checkcnfg

case "$1" in
  start)
    echo -n "Starting $srnname"
    d_start
    ;;
  stop)
    echo -n "Stopping $srnname"
    d_stop
    ;;
  restart|force-reload)
    echo -n "Restarting $srnname"
    d_stop
    sleep 1
    d_start
    ;;
  *)
    echo "Usage: $SCRIPTNAME {start|stop|restart|force-reload} user" >&2
    exit 1
    ;;
esac

exit 0
