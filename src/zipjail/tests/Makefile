.PHONY: clean default

CFLAGS += -std=c99 -pedantic -Wall -Wextra -pipe
CFLAGS += -D_POSIX_SOURCE
CFLAGS += -D_GNU_SOURCE
CFLAGS += -ggdb -pthread

SOURCE=$(wildcard *.c)
BINARY=$(SOURCE:%.c=%.out)
WORKDIR=/tmp/zipjail-workingdir

default: $(BINARY)

%.out: %.c
	$(CC) $^ $(CFLAGS) $(LDFLAGS) -o $@
	touch /tmp/zipjail-input
	rm -rf $(WORKDIR) /tmp/zipjail-dirtydir
	mkdir -p $(WORKDIR)
	echo hello > $(WORKDIR)/a.c
	echo world > $(WORKDIR)/a.py
	! ../zipjail /tmp/zipjail-input /tmp/zipjail-dirtydir ./$@

clean:
	rm -f $(BINARY)
