
.PHONY: clean default tests

CFLAGS+=-std=c99 -pedantic -Wall -Wextra -pipe #-Werror
#CFLAGS+=-ansi -pedantic -Wall -Wextra -pipe #-Werror
CFLAGS+=-I ../
CFLAGS+=-D_POSIX_SOURCE
CFLAGS+=-D_GNU_SOURCE
CFLAGS+=-ggdb -pthread
#CFLAGS+=-O2
#CFLAGS+=-m32

LDFLAGS+=-rdynamic

BINARY=soxy

default: soxy

OBJECTS:=../libtracy.a
TESTS:=tst/fork tst/mmap

tests: $(TESTS)

soxy: soxy.c
	$(CC) soxy.c $(CFLAGS) $(OBJECTS) $(LDFLAGS) -o soxy -I..

clean:
	rm *.o soxy -f $(TESTS)
