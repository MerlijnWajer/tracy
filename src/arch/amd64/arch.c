#include <stdlib.h>

#include "../../tracy.h"

#define T_SYSCALL 0x050f
#define T_INT0x80 0x80cd
#define T_SYSENTER 0x340f

int get_abi(struct tracy_event *s) {
    unsigned long sysinstr;
    struct TRACY_REGS_NAME a;

    /* TRACY_SYSCALL_OPSIZE should not be larger than sizeof(unsigned long) */
    TRACY_BUILD_BUG(sizeof(unsigned long) < TRACY_SYSCALL_OPSIZE)


    if (tracy_read_mem(s->child, &sysinstr, (char*)s->args.ip - TRACY_SYSCALL_OPSIZE,
            sizeof(char) * TRACY_SYSCALL_OPSIZE) < TRACY_SYSCALL_OPSIZE)
        return -1;

    sysinstr &= (1 << ((TRACY_SYSCALL_OPSIZE * 8) - 1));
    PTRACE_CHECK(PTRACE_GETREGS, s->child->pid, 0, &a, -1);

#if 0
    printf("CS = %lx; sysinstr = %lx; ip = %lx\n", a.cs, sysinstr, s->args.ip);
#endif

    if (a.cs == 0x23) {
        return TRACY_ABI_X86;
    }
    if (a.cs == 0x33) {
        switch (sysinstr) {
            case T_SYSCALL:
                return TRACY_ABI_AMD64;

            case T_SYSENTER:
            case T_INT0x80:
                return TRACY_ABI_X86;
        }
    }

    return -1;
}

long get_reg(struct TRACY_REGS_NAME *r, int reg, int abi) {
    switch (abi) {
        case TRACY_ABI_AMD64:
        case TRACY_ABI_X32:
            switch (reg) {
                case 0:
                    return r->rdi;
                    break;
                case 1:
                    return r->rsi;
                    break;
                case 2:
                    return r->rdx;
                    break;
                case 3:
                    return r->r10;
                    break;
                case 4:
                    return r->r8;
                    break;
                case 5:
                    return r->r9;
                    break;
                }

            break;
        case TRACY_ABI_X86:
            switch (reg) {
                case 0:
                    return r->rbx;
                    break;
                case 1:
                    return r->rcx;
                    break;
                case 2:
                    return r->rdx;
                    break;
                case 3:
                    return r->rsi;
                    break;
                case 4:
                    return r->rdi;
                    break;
                case 5:
                    return r->rbp;
                    break;
                }
            break;
    }

#pragma message "get_reg: return -1 could also be a valid register value, maybe do something else?"
    /* We should never reach this */
    return -1;
}

long set_reg(struct TRACY_REGS_NAME *r, int reg, int abi, long val) {
    switch (abi) {
        case TRACY_ABI_AMD64:
        case TRACY_ABI_X32:
            switch (reg) {
                case 0:
                    r->rdi = val;
                    break;
                case 1:
                    r->rsi = val;
                    break;
                case 2:
                    r->rdx = val;
                    break;
                case 3:
                    r->r10 = val;
                    break;
                case 4:
                    r->r8 = val;
                    break;
                case 5:
                    r->r9 = val;
                    break;
                }
            break;

        case TRACY_ABI_X86:
            switch (reg) {
                case 0:
                    r->rbx = val;
                    break;
                case 1:
                    r->rcx = val;
                    break;
                case 2:
                    r->rdx = val;
                    break;
                case 3:
                    r->rsi = val;
                    break;
                case 4:
                    r->rdi = val;
                    break;
                case 5:
                    r->rbp = val;
                    break;
                }
            break;

    }
    return 0;

}
