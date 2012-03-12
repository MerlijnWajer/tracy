
.PHONY: clean tracy default

CFLAGS+=-ansi -pedantic -Wall -Wextra -Werror
CFLAGS+=-I tracy/
CFLAGS+=-D_XOPEN_SOURCE
CFLAGS+=-ggdb
#CFLAGS+=-O2
#CFLAGS+=-m32

BINARY=soxy

default: soxy

tracy:
	$(MAKE) -C tracy

OBJECTS:=tracy/tracy.o tracy/ll.o tracy/trampy.o

soxy: main.c tracy
	$(CC) main.c $(CFLAGS) $(OBJECTS) $(LDFLAGS) -o soxy

clean:
	$(MAKE) -C tracy clean
	rm *.o soxy -f
