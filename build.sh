#!/bin/bash
dir_name=`pwd`

#######################
#build libs
#######################
echo "going to build libs"

echo "going to build hiredis"
cd ${dir_name}/lib/hiredis/from-redis-3.2.6
pwd
make clean
make static
mkdir -pv ${dir_name}/lib/hiredis/lib
mv -v libhiredis.a ${dir_name}/lib/hiredis/lib
mkdir -pv ${dir_name}/lib/hiredis/include
cp -v *.h ${dir_name}/lib/hiredis/include
cp -rv adapters  ${dir_name}/lib/hiredis/include

echo "going to build libev"
cd ${dir_name}/lib/libev/libev-4.24
./configure --prefix=${dir_name}/lib/libev
make
make install

echo "going to build glib"
cd ${dir_name}/lib/glib/glib-2.50.2
pwd
make clean
./autogen.sh  --prefix=${dir_name}/lib/glib --disable-libmount --with-pcre
make
make install

#######################
#build como
#######################
echo "going to build como"

cd ${dir_name}
pwd
make

