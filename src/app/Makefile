.PHONY: default clean check-inject

CFLAGS+=-ansi -pedantic -Wall -Wextra -Werror
CFLAGS+=-D_POSIX_SOURCE
CFLAGS+=-ggdb
CFLAGS+=-pthread
CFLAGS+=-I ../tracy
#CFLAGS+=-O2
#CFLAGS+=-m32

TESTS=ll_test loggy dotty county

default: $(TESTS)

ll_test: ll_test.c
	$(CC) ll_test.c ../tracy/ll.o $(CFLAGS) $(LDFLAGS) -o ll_test

loggy: loggy.c
	$(CC) loggy.c ../tracy/ll.o ../tracy/tracy.o ../tracy/trampy.o $(CFLAGS) $(LDFLAGS) -o loggy

dotty: dotty.c
	$(CC) dotty.c ../tracy/ll.o ../tracy/tracy.o ../tracy/trampy.o $(CFLAGS) $(LDFLAGS) -o dotty

county: county.c
	$(CC) county.c ../tracy/ll.o ../tracy/tracy.o ../tracy/trampy.o $(CFLAGS) $(LDFLAGS) -o county


clean:
	rm *.o ll_test loggy dotty county -f
