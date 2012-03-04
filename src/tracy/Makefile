.PHONY: default clean check-inject tests

CFLAGS+=-ansi -pedantic -Wall -Wextra -Werror
CFLAGS+=-D_POSIX_SOURCE
CFLAGS+=-ggdb
#CFLAGS+=-O2
#CFLAGS+=-m32

OBJECTS=tracy.o ll.o

default: $(OBJECTS)

tests: tests/hello tests/test-rwmem
tests/test-rwmem: tests/test-rwmem.o tracy.o ll.o

tracy.o: def_syscalls.h

def_syscalls.h:
	echo "#include <sys/syscall.h>" | gcc $(CFLAGS) - -E -dM | grep "define SYS" | cut -f2 -d" " | sed 's/SYS_//;s/\(.*\)/DEF_SYSCALL(&)/' > def_syscalls.h

clean:
	rm *.o def_syscalls.h test-inject -f
