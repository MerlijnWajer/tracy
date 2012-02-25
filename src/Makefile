
.PHONY: clean ptracert default

CFLAGS+=-ansi -pedantic -Wall -Wextra -Werror
CFLAGS+=-I ptracert/
CFLAGS+=-D_XOPEN_SOURCE
#CFLAGS+=-m32

BINARY=soxy

default: soxy

ptracert:
	$(MAKE) -C ptracert


OBJECTS:=ptracert/ptracert.o

soxy: main.c ptracert
	$(CC) main.c $(CFLAGS) $(OBJECTS) $(LDFLAGS) -o soxy

clean:
	$(MAKE) -C ptracert clean
	rm *.o soxy -f
