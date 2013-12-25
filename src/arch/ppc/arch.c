#include <stdlib.h>

#include "../../tracy.h"

int get_abi(struct tracy_event *s) {
    (void)s;

    return 0;
}

long get_reg(struct TRACY_REGS_NAME *r, int reg, int abi) {
    switch (abi) {
        case TRACY_ABI_PPC:
            switch (reg) {
                case 0:
                    return r->gpr[0];
                    break;
                case 1:
                    return r->gpr[1];
                    break;
                case 2:
                    return r->gpr[2];
                    break;
                case 3:
                    return r->gpr[3];
                    break;
                case 4:
                    return r->gpr[4];
                    break;
                case 5:
                    return r->gpr[5];
                    break;
                case 6:
                    return r->gpr[6];
                    break;
                case 7:
                    return r->gpr[7];
                    break;
                case 8:
                    return r->gpr[8];
                    break;
                case 9:
                    return r->gpr[9];
                    break;
                    
                }

            break;
    }

    /* We should never reach this */
    return -1;
}

long set_reg(struct TRACY_REGS_NAME *r, int reg, int abi, long val) {
    switch (abi) {
        case TRACY_ABI_PPC:
            switch (reg) {
                case 0:
                    r->gpr[0] = val;
                    break;
                case 1:
                    r->gpr[1] = val;
                    break;
                case 2:
                    r->gpr[2] = val;
                    break;
                case 3:
                    r->gpr[3] = val;
                    break;
                case 4:
                    r->gpr[4] = val;
                    break;
                case 5:
                    r->gpr[5] = val;
                    break;
                case 6:
                    r->gpr[6] = val;
                    break;
                case 7:
                    r->gpr[7] = val;
                    break;
                case 8:
                    r->gpr[8] = val;
                    break;
                case 9:
                    r->gpr[9] = val;
                    break;
                
                }
            break;

    }
    return 0;

}
