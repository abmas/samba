#!/bin/sh

if [ $# -lt 3 ]
then
    echo "Usage: $0 srcdir builddir compiler"
    exit 1
fi

uname=`uname -a`
date=`date`
srcdir=$1
builddir=$2
compiler=$3

if [ ! "x$USER" = "x" ]; then
    whoami=$USER
else 
    if [ ! "x$LOGNAME" = "x" ]; then
	whoami=$LOGNAME
    else
	whoami=`whoami || id -un`
    fi
fi

host=`hostname`

cat <<EOF
/* This file is automatically generated with "make include/build_env.h". DO NOT EDIT */

EOF