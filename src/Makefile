.PHONY: default clean check-inject tests

# Nuked -pedantic because recent glibc changed to long long unsigned ints for
# TRACY_SYSCALL_REGISTER etc. Can't print those with -pedantic...
CFLAGS+=-ansi -pedantic -Wall -Wextra -Werror -Wno-unused-result -pipe
CFLAGS+=-D_POSIX_SOURCE -D_GNU_SOURCE
CFLAGS+=-pthread -fPIC


LDFLAGS+=-rdynamic -pthread
#CFLAGS+=-O2
#CFLAGS+=-m32
#LDFLAGS+=-m32

build ?= debug

include Makerules

TRACY_HS=tracy.h ll.h tracyarch.h
TRACY_OS=tracy.o tracy-mem.o tracy-safe-fork.o tracy-modification.o \
	tracy-event.o ll.o trampy.o


uname_M = $(shell sh -c 'uname -m 2>/dev/null || echo not')

arch=
ifeq ($(uname_M),armv5tel)
arch="arm"
else ifeq ($(uname_M),armv7l)
arch="arm"
else ifeq ($(uname_M),x86_64)
arch="x86_64"
else ifeq ($(uname_M),i686)
arch="i686"
else ifeq ($(uname_M),ppc)
arch="ppc"
endif


ifeq ($(arch), "x86_64")
ARCH_HS=arch/amd64/arch.h arch/amd64/syscalls.h
ARCH_OS=arch/amd64/arch.o
else ifeq ($(arch), "arm")
ARCH_HS=arch/arm/arch.h arch/arm/syscalls.h
ARCH_OS=arch/arm/arch.o
else ifeq ($(arch), "i686")
ARCH_HS=arch/x86/arch.h arch/x86/syscalls.h
ARCH_OS=arch/x86/arch.o
else ifeq ($(arch), "ppc")
ARCH_HS=arch/ppc/arch.h arch/ppc/syscalls.h
ARCH_OS=arch/ppc/arch.o
else
ARCH_HS=
ARCH_OS=
endif

default: libtracy.a libtracy.so $(TRACY_OS) $(ARCH_OS)

# default is no longer tests

libtracy.a: $(TRACY_OS) $(ARCH_OS)
	ar cr $@ $^

libtracy.so: $(TRACY_OS) $(ARCH_OS)
	$(CC) -shared -o $@ $^ $(CFLAGS)

test_binaries=tests/hello tests/base tests/inject-simple \
	tests/thread-simple tests/thread-simple-prog tests/fork \
	tests/fork-prog tests/vfork-prog tests/bounce tests/bash \
	tests/raw-clone tests/deny tests/attach tests/metronome \
	tests/sig_suppress tests/async-inject tests/redirect tests/wxorx \
	tests/abi tests/attach-detach
	#tests/rwmem


tests: $(test_binaries)
#tests/rwmem: tests/rwmem.o $(TRACY_OS) $(ARCH_OS)
tests/wxorx: tests/wxorx.o $(TRACY_OS) $(ARCH_OS)
tests/abi: tests/abi.o $(TRACY_OS) $(ARCH_OS)
tests/base: tests/base.o $(TRACY_OS) $(ARCH_OS)
tests/sig_suppress: tests/sig_suppress.o $(TRACY_OS) $(ARCH_OS)
tests/async-inject: tests/async-inject.o $(TRACY_OS) $(ARCH_OS)
tests/redirect: tests/redirect.o $(TRACY_OS) $(ARCH_OS)
tests/bash: tests/bash.o $(TRACY_OS) $(ARCH_OS)
tests/deny: tests/deny.o $(TRACY_OS) $(ARCH_OS)
tests/inject-simple: tests/inject-simple.o $(TRACY_OS) $(ARCH_OS)
tests/thread-simple: tests/thread-simple.o $(TRACY_OS) $(ARCH_OS)
tests/thread-simple-prog: tests/thread-simple-prog.o
tests/fork: tests/fork.o $(TRACY_OS) $(ARCH_OS)
tests/bounce: tests/bounce.o trampy.o
tests/attach: tests/attach.o $(TRACY_OS) $(ARCH_OS)
tests/attach-detach: tests/attach-detach.o $(TRACY_OS) $(ARCH_OS)
tests/metronome: tests/metronome.o

#check-rwmem: tests/rwmem tests/hello
#	tests/rwmem tests/hello

# Tracy core
tracy.o: def_syscalls.h def_signals.h $(TRACY_HS) $(ARCH_HS)
tracy-mem.o: $(TRACY_HS)
tracy-safe-fork.o: trampy.h $(TRACY_HS)
tracy-modification.o: $(TRACY_HS)
ll.o: ll.h

# Tracy dependent test files.
tests/redirect.o: $(TRACY_HS)
tests/wxorx.o: $(TRACY_HS)
tests/bash.o: $(TRACY_HS)
tests/abi.o: $(TRACY_HS)
tests/deny.o: $(TRACY_HS)
tests/sig_suppress.o: $(TRACY_HS)
tests/async-inject.o: $(TRACY_HS)
tests/base.o: $(TRACY_HS)
tests/inject-simple.o: $(TRACY_HS)
tests/thread-simple.o: $(TRACY_HS)
tests/fork.o: $(TRACY_HS)
#tests/rwmem.o: $(TRACY_HS)
tests/bouce.o: trampy.h
tests/attach.o: $(TRACY_HS)
tests/attach-detach.o: $(TRACY_HS)

def_syscalls.h:
	echo "#include <sys/syscall.h>" | $(CC) $(CFLAGS) - -E -dM \
		| grep "define SYS" | cut -f2 -d" " | \
		sed 's/SYS_//;s/\(.*\)/DEF_SYSCALL(&)/' > def_syscalls.h


# XXX: Depending on uname -m is bad because it doesn't allow us to build tracy
# for say x86. (Although I don't think you want that on amd64, because of ABI
# mixing) Still, we need a build option for it. Like make platform=amd64

ifeq ($(arch),"x86_64")
#
#					 *** AMD64 ***
#
arch/amd64/arch.o: $(TRACY_HS) arch/amd64/syscalls.h
arch/amd64/syscalls.h: $(TRACY_HS) arch/amd64/syscall_amd64.h \
	arch/amd64/syscall_x86.h arch/amd64/syscall_x32.h

arch/amd64/syscall_amd64.h:
	echo "#include <sys/syscall.h>" | $(CC) $(CFLAGS) - -E -dM  | \
		grep "define SYS" | cut -f2 -d" " | \
		( echo "#define DEF_SYSCALL(NAME) {#NAME, SYS_ ## NAME}," ; \
		sed 's/SYS_//;s/\(.*\)/DEF_SYSCALL(&)/' ; echo "{NULL, -1}") \
		| $(CC) $(CFLAGS)  - -E  | ( echo "#include <sys/syscall.h>" ; cat ) \
		| grep -v '# ' | $(CC) $(CFLAGS) -E - | grep '{.*' \
		> arch/amd64/syscall_amd64.h
arch/amd64/syscall_x86.h:
	echo "#include <sys/syscall.h>" | $(CC) $(CFLAGS) - -E  -m32 -dM | \
		grep "define SYS" | cut -f2 -d" " | \
		( echo "#define DEF_SYSCALL(NAME) {#NAME, SYS_ ## NAME}," ; \
		sed 's/SYS_//;s/\(.*\)/DEF_SYSCALL(&)/' ; echo "{NULL, -1}") \
		| $(CC) $(CFLAGS) - -E -m32   | ( echo "#include <sys/syscall.h>" ; cat ) \
		| grep -v '# ' | $(CC) $(CFLAGS) - -E -m32 | grep '{.*' \
		> arch/amd64/syscall_x86.h
arch/amd64/syscall_x32.h:
	echo "#include <sys/syscall.h>" | $(CC) $(CFLAGS) - -E  -mx32 -dM | \
		grep "define SYS" | cut -f2 -d" " | \
		( echo "#define DEF_SYSCALL(NAME) {#NAME, SYS_ ## NAME}," ; \
		sed 's/SYS_//;s/\(.*\)/DEF_SYSCALL(&)/' ; echo "{NULL, -1}") \
		| $(CC) $(CFLAGS) - -E -mx32   | ( echo "#include <sys/syscall.h>" ; cat ) \
		| grep -v '# ' | $(CC) $(CFLAGS) - -E -mx32 | grep '{.*' \
		> arch/amd64/syscall_x32.h
else ifeq ($(arch),"arm")
#
#					 *** ARM ***
#
arch/arm/arch.o: $(TRACY_HS) arch/arm/syscalls.h
arch/arm/syscalls.h: $(TRACY_HS) arch/arm/syscall_eabi.h

arch/arm/syscall_eabi.h:
	echo "#include <sys/syscall.h>" | $(CC) $(CFLAGS) - -E -dM | \
		grep "define SYS" | cut -f2 -d" " \
		| ( echo "#define DEF_SYSCALL(NAME) {#NAME, SYS_ ## NAME}," ; \
		sed 's/SYS_//;s/\(.*\)/DEF_SYSCALL(&)/' ; echo "{NULL, -1}") \
		| $(CC) $(CFLAGS)  - -E  | ( echo "#include <sys/syscall.h>" ; cat ) \
		| grep -v '# '| $(CC) $(CFLAGS) -E - | grep '{.*' \
		> arch/arm/syscall_eabi.h
else ifeq ($(arch),"i686")
#
#					 *** x86 ***
#
arch/x86/arch.o: $(TRACY_HS) arch/x86/syscalls.h
arch/x86/syscalls.h: $(TRACY_HS) arch/x86/syscall_x86.h

arch/x86/syscall_x86.h:
	echo "#include <sys/syscall.h>" | $(CC) $(CFLAGS) - -E -dM | \
		grep "define SYS" | cut -f2 -d" " \
		| ( echo "#define DEF_SYSCALL(NAME) {#NAME, SYS_ ## NAME}," ; \
		sed 's/SYS_//;s/\(.*\)/DEF_SYSCALL(&)/' ; echo "{NULL, -1}") \
		| $(CC) $(CFLAGS)  - -E  | ( echo "#include <sys/syscall.h>" ; cat ) \
		| grep -v '# '| $(CC) $(CFLAGS) -E - | grep '{.*' \
		> arch/x86/syscall_x86.h
else ifeq ($(arch),"ppc")
#
#					 *** ppc ***
#
arch/ppc/arch.o: $(TRACY_HS) arch/ppc/syscalls.h
arch/ppc/syscalls.h: $(TRACY_HS) arch/ppc/syscall_ppc.h

arch/ppc/syscall_ppc.h:
	echo "#include <sys/syscall.h>" | $(CC) $(CFLAGS) - -E -dM | \
		grep "define SYS" | cut -f2 -d" " \
		| ( echo "#define DEF_SYSCALL(NAME) {#NAME, SYS_ ## NAME}," ; \
		sed 's/SYS_//;s/\(.*\)/DEF_SYSCALL(&)/' ; echo "{NULL, -1}") \
		| $(CC) $(CFLAGS)  - -E  | ( echo "#include <sys/syscall.h>" ; cat ) \
		| grep -v '# '| $(CC) $(CFLAGS) -E - | grep '{.*' \
		> arch/ppc/syscall_ppc.h

endif

clean:
	rm *.o *.a *.so def_syscalls.h tests/*.o -f $(test_binaries) \
		arch/amd64/syscall_*.h arch/amd64/*.o \
		arch/arm/syscall_*.h arch/arm/*.o \
		arch/x86/syscall_*.h arch/x86/*.o \
		arch/ppc/syscall_*.h arch/ppc/*.o
