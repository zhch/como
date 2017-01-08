uname_S := $(shell sh -c 'uname -s 2>/dev/null || echo not')

CC=gcc
CFLAG=-O2 -std=c99 -pedantic -DREDIS_STATIC=''

WARN=-Wall -W

PREFIX=../lib

INCLUDE=-I.

all:como
	@echo ""
	@echo "Build como done"
	@echo ""

como:como.o
	$(CC) $^  $(LIB)  -o $@
	rm -rvf *.o

%.o:%.c
	$(CC) -c $^ -o $@ ${INCLUDE} ${CFLAG}

clean:
	rm -rf *.o  *.a
