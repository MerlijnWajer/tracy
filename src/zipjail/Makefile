.PHONY: clean default

CFLAGS += -std=c99 -pedantic -Wall -Wextra -pipe
CFLAGS += -D_POSIX_SOURCE -D_GNU_SOURCE -pthread -static -s

LDFLAGS += -rdynamic

BINARY = zipjail

default: zipjail

OBJECTS:=../libtracy.a

zipjail: zipjail.c $(OBJECTS)
	$(CC) zipjail.c $(CFLAGS) $(OBJECTS) $(LDFLAGS) -o zipjail -I..

clean:
	rm -f *.o zipjail
