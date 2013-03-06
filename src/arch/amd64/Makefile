.PHONY: clean default

default: syscall_x86.h syscall_amd64.h

syscall_amd64.h:
	echo "#include <sys/syscall.h>" | gcc $(CFLAGS) - -E -dM  | grep "define SYS" | cut -f2 -d" " | ( echo "#define DEF_SYSCALL(NAME) {#NAME, SYS_ ## NAME}," ; sed 's/SYS_//;s/\(.*\)/DEF_SYSCALL(&)/' ; echo "{NULL, -1}") | gcc $(CFLAGS)  - -E  | ( echo "#include <sys/syscall.h>" ; cat ) | gcc $(CFLAGS) -E - | grep -v '#' > syscall_amd64.h

syscall_x86.h:
	echo "#include <sys/syscall.h>" | gcc $(CFLAGS) - -E  -m32 -dM | grep "define SYS" | cut -f2 -d" " | ( echo "#define DEF_SYSCALL(NAME) {#NAME, SYS_ ## NAME}," ; sed 's/SYS_//;s/\(.*\)/DEF_SYSCALL(&)/' ; echo "{NULL, -1}") | gcc $(CFLAGS) - -E -m32   | ( echo "#include <sys/syscall.h>" ; cat ) | gcc $(CFLAGS) - -E -m32 | grep -v '#' > syscall_x86.h

clean:
	rm syscall_*.h -v
