#include "../../tracy.h"

int get_abi(struct tracy_event *s) {
    (void)s;
    return TRACY_ABI_NATIVE;
}

long get_reg(struct TRACY_REGS_NAME *r, int reg, int abi) {
    (void) abi;
    /* We have only one ABI */

    switch (reg) {
        case 0:
            return r->ebx;
            break;
        case 1:
            return r->ecx;
            break;
        case 2:
            return r->edx;
            break;
        case 3:
            return r->esi;
            break;
        case 4:
            return r->edi;
            break;
        case 5:
            return r->ebp;
            break;
        }

    return -1;
}

long set_reg(struct TRACY_REGS_NAME *r, int reg, int abi, long val) {
    (void) abi;
    /* We have only one ABI */

    switch (reg) {
        case 0:
            r->ebx = val;
            break;
        case 1:
            r->ecx = val;
            break;
        case 2:
            r->edx = val;
            break;
        case 3:
            r->esi = val;
            break;
        case 4:
            r->edi = val;
            break;
        case 5:
            r->ebp = val;
            break;
        }
    return 0;
}
