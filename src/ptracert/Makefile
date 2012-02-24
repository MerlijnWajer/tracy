.PHONY: default clean

CFLAGS+=-ansi -pedantic -Wall -Wextra -Werror
CFLAGS+=-D_POSIX_SOURCE

OBJECTS=ptracert.o

default: $(OBJECTS)

%.o:	%.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm *.o -f
