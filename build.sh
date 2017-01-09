#!/bin/bash
dir_name=`pwd`

#######################
#build libs
#######################
echo "going to build libs"

echo "going to build glib"
cd ${dir_name}/lib/glib/glib-2.50.2
pwd
make clean
./configure --prefix=${dir_name}/lib/glib --disable-libmount --with-pcre
make
make install

#######################
#build como
#######################
echo "going to build como"

cd ${dir_name}
pwd
make
