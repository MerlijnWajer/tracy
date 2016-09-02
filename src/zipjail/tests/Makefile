.PHONY: clean default

CFLAGS += -std=c99 -pedantic -Wall -Wextra -pipe
CFLAGS += -D_POSIX_SOURCE
CFLAGS += -D_GNU_SOURCE
CFLAGS += -ggdb -pthread

SOURCE=$(wildcard *.c)
BINARY32=$(SOURCE:%.c=%-x86.out)
BINARY64=$(SOURCE:%.c=%-x64.out)
RESULTS=$(BINARY32:%.out=%.result)
RESULTS+=$(BINARY64:%.out=%.result)
WORKDIR=/tmp/zipjail-workingdir

default: $(BINARY32) $(BINARY64) $(RESULTS)

%-x86.out: %.c
	$(CC) $^ $(CFLAGS) $(LDFLAGS) -o $@ -m32

%-x64.out: %.c
	$(CC) $^ $(CFLAGS) $(LDFLAGS) -o $@

%.result: %.out
	touch /tmp/zipjail-input
	rm -rf $(WORKDIR) /tmp/zipjail-dirtydir
	mkdir -p $(WORKDIR)
	echo hello > $(WORKDIR)/a.c
	echo world > $(WORKDIR)/a.py
	! ../zipjail /tmp/zipjail-input /tmp/zipjail-dirtydir ./$^

clean:
	rm -f $(BINARY32) $(BINARY64)
