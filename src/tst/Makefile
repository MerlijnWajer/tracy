.PHONY: default clean check-inject

CFLAGS+=-ansi -pedantic -Wall -Wextra -Werror
CFLAGS+=-D_POSIX_SOURCE
CFLAGS+=-ggdb
CFLAGS+=-I ../tracy
#CFLAGS+=-O2
#CFLAGS+=-m32

TESTS=ll_test loggy

default: $(TESTS)

ll_test: ll_test.c
	$(CC) ll_test.c ../tracy/ll.o $(CFLAGS) $(LDFLAGS) -o ll_test

loggy: loggy.c
	$(CC) loggy.c ../tracy/ll.o ../tracy/tracy.o $(CFLAGS) $(LDFLAGS) -o loggy


clean:
	rm *.o ll_test loggy -f
