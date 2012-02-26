.PHONY: default clean

CFLAGS+=-ansi -pedantic -Wall -Wextra -Werror
CFLAGS+=-D_POSIX_SOURCE
CFLAGS=-ggdb
#CFLAGS+=-m32

OBJECTS=tracy.o ll.o

default: $(OBJECTS)

tracy.o: def_syscalls.h

def_syscalls.h:
	echo "#include <sys/syscall.h>" | gcc - -E -dM | grep "define SYS" | cut -f2 -d" " | sed 's/SYS_//;s/\(.*\)/DEF_SYSCALL(&)/' > def_syscalls.h

%.o:	%.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm *.o def_syscalls.h -f
