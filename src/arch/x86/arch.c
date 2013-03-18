#include "../../tracy.h"

int get_abi(struct tracy_event *s) {
    return TRACY_ABI_NATIVE;
}

long get_reg(struct TRACY_REGS_NAME *r, int reg, int abi) {
}

long set_reg(struct TRACY_REGS_NAME *r, int reg, int abi, long val) {
}
