
#include <syscall.h>

#ifdef __x86_64__
#define SYSCALL_REG "rax"
#define ENTER_KERNEL "syscall\n"

#elif defined(__i386__)
#define SYSCALL_REG "a"
#define ENTER_KERNEL "int $0x80\n"

#else
#error Architecture not supported by trampy

#endif


void DO_NOT_CALL_ME_IF_YOU_WANT_TO_LIVE() {
    __asm__(""\
".globl start_label\n"\
"start_label:\n"\
ENTER_KERNEL
);
    while(1) {
            __asm__(
                    ENTER_KERNEL
                    ::SYSCALL_REG
                    (__NR_sched_yield));
    }

    return;
}

int I_AM_THE_END_OF_IT_ALL() {
    return 42;
}

