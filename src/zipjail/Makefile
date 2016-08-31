.PHONY: clean default

CFLAGS+=-std=c99 -pedantic -Wall -Wextra -pipe #-Werror
#CFLAGS+=-ansi -pedantic -Wall -Wextra -pipe #-Werror
CFLAGS+=-I ../
CFLAGS+=-D_POSIX_SOURCE
CFLAGS+=-D_GNU_SOURCE
CFLAGS+=-ggdb -pthread
#CFLAGS+=-O2
#CFLAGS+=-m32

LDFLAGS+=-rdynamic

BINARY=zipjail

default: zipjail

OBJECTS:=../libtracy.a

zipjail: zipjail.c $(OBJECTS)
	$(CC) zipjail.c $(CFLAGS) $(OBJECTS) $(LDFLAGS) -o zipjail -I..

clean:
	rm -f *.o zipjail
