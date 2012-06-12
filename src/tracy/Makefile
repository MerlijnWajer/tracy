.PHONY: default clean check-inject tests

CFLAGS+=-ansi -pedantic -Wall -Wextra -Werror -pipe
CFLAGS+=-D_POSIX_SOURCE -D_GNU_SOURCE
CFLAGS+=-ggdb

LDFLAGS+=-rdynamic -pthread
#CFLAGS+=-O2
#CFLAGS+=-m32

OBJECTS=tracy.o ll.o trampy.o

default: $(OBJECTS) tests

test_binaries=tests/hello tests/rwmem tests/base tests/inject-simple \
	tests/thread-simple tests/thread-simple-prog tests/fork \
	tests/fork-prog tests/vfork-prog tests/bounce tests/bash

tests: $(test_binaries)
tests/rwmem: tests/rwmem.o tracy.o ll.o trampy.o
tests/base: tests/base.o tracy.o ll.o trampy.o
tests/bash: tests/bash.o tracy.o ll.o trampy.o
tests/inject-simple: tests/inject-simple.o tracy.o ll.o trampy.o
tests/thread-simple: tests/thread-simple.o tracy.o ll.o trampy.o
tests/thread-simple-prog: tests/thread-simple-prog.o
tests/fork: tests/fork.o tracy.o ll.o trampy.o
tests/bounce: tests/bounce.o trampy.o

check-rwmem: tests/rwmem tests/hello
	tests/rwmem tests/hello

tracy.o: def_syscalls.h

def_syscalls.h:
	echo "#include <sys/syscall.h>" | gcc $(CFLAGS) - -E -dM \
		| grep "define SYS" | cut -f2 -d" " | \
		sed 's/SYS_//;s/\(.*\)/DEF_SYSCALL(&)/' > def_syscalls.h

clean:
	rm *.o def_syscalls.h tests/*.o -f $(test_binaries)

