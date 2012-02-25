.PHONY: default clean

CFLAGS+=-ansi -pedantic -Wall -Wextra -Werror
CFLAGS+=-D_POSIX_SOURCE
CFLAGS=-ggdb
#CFLAGS+=-m32

OBJECTS=ptracert.o ll.o

default: $(OBJECTS)

%.o:	%.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm *.o -f
