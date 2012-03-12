
#include <syscall.h>

void DO_NOT_CALL_ME_IF_YOU_WANT_TO_LIVE() {
    __asm__(""\
".globl start_label\n"\
"start_label:\n"\
"syscall\n"\
);
    while(1) {
            __asm__("syscall"
                    ::"rax"(__NR_sched_yield));
    }

    return;
}
int I_AM_THE_END_OF_IT_ALL() {
    return 42;
}

