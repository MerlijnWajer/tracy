static struct tracy_abi_syscall x86_sc[] = {
#include "syscall_x86.h"
};


struct tracy_abi_syscall* syscalls_abi[TRACY_ABI_COUNT] = {
    x86_sc
};

