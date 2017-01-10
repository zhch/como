#!/bin/bash
ulimit -c unlimited &> /dev/null

dir_name=`pwd`

export LD_LIBRARY_PATH=${dir_name}/lib/glib
mkdir -p ${dir_name}/logs
nohup ./como > ${dir_name}/logs/como.out 2>&1 &

echo "start como done."
