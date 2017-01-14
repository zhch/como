uname_S := $(shell sh -c 'uname -s 2>/dev/null || echo not')

CC=gcc
CFLAG=-O0 -std=c99 -pedantic -ggdb -Wall

PREFIX=../lib

INCLUDE=-I. \
	-I${PREFIX}/glib/lib/glib-2.0/include -I${PREFIX}/glib/include/glib-2.0 \
    -I${PREFIX}/libev/include

LIB=-lpthread -lz -lrt \
    ${PREFIX}/libev/lib/libev.a \
    -L${PREFIX}/glib/lib  -lm -lglib-2.0

all:como
	@echo ""
	@echo "Build como done"
	@echo ""

como:como.o resp.o
	$(CC) $^  $(LIB)  -o $@
	rm -rvf *.o

%.o:%.c
	$(CC) -c $^ -o $@ ${INCLUDE} ${CFLAG}

clean:
	rm -rf *.o  *.a
