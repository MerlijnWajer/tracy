.PHONY: default clean check-inject tests

CFLAGS+=-ansi -pedantic -Wall -Wextra -Werror -Wno-unused-result -pipe
CFLAGS+=-D_POSIX_SOURCE -D_GNU_SOURCE
CFLAGS+=-pthread

LDFLAGS+=-rdynamic -pthread
#CFLAGS+=-O2
#CFLAGS+=-m32
#LDFLAGS+=-m32

build ?= debug

include Makerules

TRACY_HS=tracy.h ll.h tracyarch.h
TRACY_OS=tracy.o tracy-mem.o tracy-safe-fork.o tracy-modification.o \
	tracy-event.o ll.o trampy.o

default: libtracy.a $(TRACY_OS) tests

libtracy.a: $(TRACY_OS)
	ar cr $@ $^

test_binaries=tests/hello tests/rwmem tests/base tests/inject-simple \
	tests/thread-simple tests/thread-simple-prog tests/fork \
	tests/fork-prog tests/vfork-prog tests/bounce tests/bash \
	tests/raw-clone tests/deny tests/attach tests/metronome \
	tests/sig_suppress tests/async-inject tests/redirect

tests: $(test_binaries)
tests/rwmem: tests/rwmem.o $(TRACY_OS)
tests/base: tests/base.o $(TRACY_OS)
tests/sig_suppress: tests/sig_suppress.o $(TRACY_OS)
tests/async-inject: tests/async-inject.o $(TRACY_OS)
tests/redirect: tests/redirect.o $(TRACY_OS)
tests/bash: tests/bash.o $(TRACY_OS)
tests/deny: tests/deny.o $(TRACY_OS)
tests/inject-simple: tests/inject-simple.o $(TRACY_OS)
tests/thread-simple: tests/thread-simple.o $(TRACY_OS)
tests/thread-simple-prog: tests/thread-simple-prog.o
tests/fork: tests/fork.o $(TRACY_OS)
tests/bounce: tests/bounce.o trampy.o
tests/attach: tests/attach.o $(TRACY_OS)
tests/metronome: tests/metronome.o

check-rwmem: tests/rwmem tests/hello
	tests/rwmem tests/hello

# Tracy core
tracy.o: def_syscalls.h def_signals.h $(TRACY_HS)
tracy-mem.o: $(TRACY_HS)
tracy-safe-fork.o: trampy.h $(TRACY_HS)
tracy-modification.o: $(TRACY_HS)
ll.o: ll.h

# Tracy dependent test files.
tests/redirect.o: $(TRACY_HS)
tests/bash.o: $(TRACY_HS)
tests/deny.o: $(TRACY_HS)
tests/sig_suppress.o: $(TRACY_HS)
tests/async-inject.o: $(TRACY_HS)
tests/base.o: $(TRACY_HS)
tests/inject-simple.o: $(TRACY_HS)
tests/thread-simple.o: $(TRACY_HS)
tests/fork.o: $(TRACY_HS)
tests/rwmem.o: $(TRACY_HS)
tests/bouce.o: trampy.h
tests/attach.o: $(TRACY_HS)


def_syscalls.h:
	echo "#include <sys/syscall.h>" | gcc $(CFLAGS) - -E -dM \
		| grep "define SYS" | cut -f2 -d" " | \
		sed 's/SYS_//;s/\(.*\)/DEF_SYSCALL(&)/' > def_syscalls.h

clean:
	rm *.o *.a def_syscalls.h tests/*.o -f $(test_binaries)

