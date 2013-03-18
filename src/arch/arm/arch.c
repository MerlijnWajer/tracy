#include <stdlib.h>

#include "../../tracy.h"

int get_abi(struct tracy_event *s) {
    (void)s;

    return 0;
}

long get_reg(struct TRACY_REGS_NAME *r, int reg, int abi) {
    switch (abi) {
        case TRACY_ABI_EABI:
        case TRACY_ABI_OABI:
            switch (reg) {
                case 0:
                    return r->ARM_r0;
                    break;
                case 1:
                    return r->ARM_r1;
                    break;
                case 2:
                    return r->ARM_r2;
                    break;
                case 3:
                    return r->ARM_r3;
                    break;
                case 4:
                    return r->ARM_r4;
                    break;
                case 5:
                    return r->ARM_r5;
                    break;
                }

            break;
    }

    /* We should never reach this */
    return -1;
}

long set_reg(struct TRACY_REGS_NAME *r, int reg, int abi, long val) {
    switch (abi) {
        case TRACY_ABI_EABI:
        case TRACY_ABI_OABI:
            switch (reg) {
                case 0:
                    r->ARM_r0 = val;
                    break;
                case 1:
                    r->ARM_r1 = val;
                    break;
                case 2:
                    r->ARM_r2 = val;
                    break;
                case 3:
                    r->ARM_r3 = val;
                    break;
                case 4:
                    r->ARM_r4 = val;
                    break;
                case 5:
                    r->ARM_r5 = val;
                    break;
                }
            break;

    }
    return 0;

}
