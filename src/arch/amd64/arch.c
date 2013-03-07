#include <stdlib.h>

#include "../../tracy.h"

#define T_SYSCALL 0x050f
#define T_INT0x80 0x340f
#define T_SYSENTER 0x80cd

int get_abi(struct tracy_event *s) {
    char *buf;
    unsigned long sysinstr;

    struct TRACY_REGS_NAME a;

    /* TODO XXX Get rid of malloc and just use the stack? */
    buf = malloc(sizeof(char) * sizeof(unsigned long));
    tracy_read_mem(s->child, buf, (char*)s->args.ip - TRACY_SYSCALL_OPSIZE,
            sizeof(char) * TRACY_SYSCALL_OPSIZE);

    sysinstr = *(unsigned long*)buf;
    free(buf);

    PTRACE_CHECK(PTRACE_GETREGS, s->child->pid, 0, &a, -1);

    printf("CS = %lx; sysinstr = %lx; ip = %lx\n", a.cs, sysinstr, s->args.ip);

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
