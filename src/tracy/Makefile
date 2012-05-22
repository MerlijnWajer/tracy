.PHONY: default clean check-inject tests

CFLAGS+=-ansi -pedantic -Wall -Wextra -Werror -pipe
CFLAGS+=-D_POSIX_SOURCE -D_GNU_SOURCE
CFLAGS+=-ggdb

LDFLAGS+=-rdynamic
#CFLAGS+=-O2
#CFLAGS+=-m32

OBJECTS=tracy.o ll.o trampy.o

default: $(OBJECTS) tests

tests: tests/hello tests/test-rwmem tests/tracy-base tests/tracy-inject-simple \
	tests/tracy-thread-simple tests/tracy-thread-simple-prog tests/tracy-fork \
	tests/tracy-fork-prog
tests/test-rwmem: tests/test-rwmem.o tracy.o ll.o trampy.o
tests/tracy-base: tests/tracy-base.o tracy.o ll.o trampy.o
tests/tracy-inject-simple: tests/tracy-inject-simple.o tracy.o ll.o trampy.o
tests/tracy-thread-simple: tests/tracy-thread-simple.o tracy.o ll.o trampy.o
tests/tracy-thread-simple-prog: CFLAGS+=-pthread
tests/tracy-thread-simple-prog: LDFLAGS+=-pthread
tests/tracy-thread-simple-prog: tests/tracy-thread-simple-prog.o
tests/tracy-fork: tests/tracy-fork.o tracy.o ll.o trampy.o
tests/tracy-fork-prog: tests/tracy-fork-prog.o

check-rwmem: tests/test-rwmem tests/hello
	tests/test-rwmem tests/hello

tracy.o: def_syscalls.h

def_syscalls.h:
	echo "#include <sys/syscall.h>" | gcc $(CFLAGS) - -E -dM \
		| grep "define SYS" | cut -f2 -d" " | \
		sed 's/SYS_//;s/\(.*\)/DEF_SYSCALL(&)/' > def_syscalls.h

clean:
	rm *.o def_syscalls.h tests/test-rwmem tests/tracy_base tests/hello \
		tests/*.o -f
