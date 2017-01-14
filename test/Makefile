uname_S := $(shell sh -c 'uname -s 2>/dev/null || echo not')

CC=gcc
CFLAG=-O0 -std=c99 -pedantic -ggdb -Wall
PREFIX=../lib

INCLUDE=-I./ -I../src\
-I${PREFIX}/glib/lib/glib-2.0/include \
-I${PREFIX}/glib/include/glib-2.0  \
-I${PREFIX}/libev/include\
-I${PREFIX}/hiredis/include

LIB=-lpthread -lz -lrt \
${PREFIX}/libev/lib/libev.a \
-L${PREFIX}/glib/lib  -lm -lglib-2.0  \
${PREFIX}/hiredis/lib/libhiredis.a

all:resp_echo resp_client
	@echo ""
	@echo "Build all tests finished"
	@echo ""




resp_echo:test_resp_echo install_test_resp_echo
	@echo ""
	@echo "Build test_resp_echo finished"
	@echo ""

test_resp_echo:test_resp_echo.o ../src/resp.o
	$(CC) $^  $(LIB)  -o $@
	rm -rvf *.o

install_test_resp_echo:common_install
	mv test_resp_echo tests




resp_client:test_resp_client install_resp_client
	@echo ""
	@echo "Build test_resp_client finished"
	@echo ""

test_resp_client:test_resp_client.o
	$(CC) $^  $(LIB)  -o $@
	rm -rvf *.o

install_resp_client:common_install
	mv test_resp_client tests




common_install:
	mkdir -pv tests/lib
	cp -r ../lib/glib/lib tests/lib/glib
	mkdir -pv tests/cfg
	cp tests.cfg tests/cfg


%.o:%.c
	$(CC) -c $^ -o $@ ${INCLUDE} ${CFLAG}

clean:
	rm -rvf *.o  *.a tests
