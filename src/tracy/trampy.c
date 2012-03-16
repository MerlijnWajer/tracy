
#include <syscall.h>

#ifdef __x86_64__
#define SET_SYSCALL "rax"
#define ENTER_KERNEL "syscall\n"
#define TRACY_SYSCALL_BASE (0x0)

#elif defined(__i386__)
#define SET_SYSCALL "a"
#define ENTER_KERNEL "int $0x80\n"
#define TRACY_SYSCALL_BASE (0x0)

#elif defined(__arm__)
#define SET_SYSCALL "n"
#define ENTER_KERNEL "swi %0\n"
/* EABI SWI_BASE */
#define TRACY_SYSCALL_BASE (0x900000)

#else
#error Architecture not supported by trampy on Linux

#endif

#define MAKE_SYSCALL(CALL_NR) \
    __asm__( \
        ENTER_KERNEL \
        ::SET_SYSCALL( \
            TRACY_SYSCALL_BASE + CALL_NR \
        ) \
    )

void DO_NOT_CALL_ME_IF_YOU_WANT_TO_LIVE() {
    /* Setup label in which we can hook */
    __asm__(""\
".globl start_label\n"\
"start_label:\n"
);
    /* This syscall is to be replaced with the
     * appropriate fork/clone.
     *
     * This is an unrolled loop for the sake of clarity.
     */
    MAKE_SYSCALL(SYS_sched_yield);

    /* Now keep making sched_yield syscalls untill
     * tracer sets us back.
     */
    while(1) {
        MAKE_SYSCALL(SYS_sched_yield);
    }

    return;
}

int I_AM_THE_END_OF_IT_ALL() {
    return 42;
}

