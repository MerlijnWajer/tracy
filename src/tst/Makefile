.PHONY: default clean check-inject

CFLAGS+=-ansi -pedantic -Wall -Wextra -Werror
CFLAGS+=-D_POSIX_SOURCE
CFLAGS+=-ggdb
CFLAGS+=-I ../tracy
#CFLAGS+=-O2
#CFLAGS+=-m32

TESTS=ll_test

default: $(TESTS)

ll_test: ll_test.c
	$(CC) ll_test.c ../tracy/ll.o $(CFLAGS) $(LDFLAGS) -o ll_test

clean:
	rm *.o ll_test
