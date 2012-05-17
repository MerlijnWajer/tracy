
.PHONY: clean tracy default tests

CFLAGS+=-std=c99 -pedantic -Wall -Wextra -Werror -pipe
CFLAGS+=-I tracy/
CFLAGS+=-D_POSIX_SOURCE
CFLAGS+=-D_GNU_SOURCE
CFLAGS+=-ggdb
CFLAGS+=-D_SOXY_IPV6_
#CFLAGS+=-O2
#CFLAGS+=-m32

LDFLAGS+=-rdynamic

BINARY=soxy

default: soxy

tracy:
	$(MAKE) -C tracy

OBJECTS:=tracy/tracy.o tracy/ll.o tracy/trampy.o
TESTS:=tst/fork tst/mmap

tests: $(TESTS)

soxy: soxy.c tracy
	$(CC) soxy.c $(CFLAGS) $(OBJECTS) $(LDFLAGS) -o soxy -Itracy

clean:
	$(MAKE) -C tracy clean
	rm *.o soxy -f $(TESTS)
