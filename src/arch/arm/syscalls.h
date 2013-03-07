static struct tracy_abi_syscall eabi_sc[] = {
#include "syscall_eabi.h"
};


struct tracy_abi_syscall* syscalls_abi[TRACY_ABI_COUNT] = {
    eabi_sc,
};
