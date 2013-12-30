static struct tracy_abi_syscall ppc_sc[] = {
#include "syscall_ppc.h"
};


struct tracy_abi_syscall* syscalls_abi[TRACY_ABI_COUNT] = {
    ppc_sc,
};
