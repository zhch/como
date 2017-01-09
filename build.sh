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
./autogen.sh  --prefix=${dir_name}/lib/glib --disable-libmount --with-pcre
make
make install

echo "going to build libev"
cd ${dir_name}/lib/libev/libev-4.24
./configure
make
make install

#######################
#build como
#######################
echo "going to build como"

cd ${dir_name}
pwd
make

