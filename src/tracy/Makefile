.PHONY: default clean check-inject

CFLAGS+=-ansi -pedantic -Wall -Wextra -Werror
CFLAGS+=-D_POSIX_SOURCE
CFLAGS=-ggdb
#CFLAGS+=-O2
#CFLAGS+=-m32

OBJECTS=tracy.o ll.o

default: $(OBJECTS)

check-inject: test-inject
	./test-inject

test-inject: test-inject.o tracy.o ll.o

tracy.o: def_syscalls.h

def_syscalls.h:
	echo "#include <sys/syscall.h>" | gcc - -E -dM | grep "define SYS" | cut -f2 -d" " | sed 's/SYS_//;s/\(.*\)/DEF_SYSCALL(&)/' > def_syscalls.h

clean:
	rm *.o def_syscalls.h test-inject -f
