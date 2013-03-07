static struct tracy_abi_syscall amd64_sc[] = {
#include "syscall_amd64.h"
};

static struct tracy_abi_syscall x86_sc[] = {
#include "syscall_x86.h"
};

static struct tracy_abi_syscall x32_sc[] = {
#include "syscall_x32.h"
};

struct tracy_abi_syscall* syscalls_abi[TRACY_ABI_COUNT] = {
    amd64_sc,
    x86_sc,
    x32_sc
};
