/* trampy.c provides a piece of PAC (Position Agnostic Code) that can be
 * injected into traced processes to securily fork them. That is,
 * it throws the traced process and its newly forked child into a loop
 * allowing tracy to attach to the child and afterwards restore both processes
 * as if nothing happened, save for the original syscall.
 *
 * XXX: Trampy will NOT work when compiled with -fPIC (position independent code)
 * due to its modification of %ebx on x86 architectures, in fact it probably
 * won't even compile as GCC tends to complain about inline assembly modifying
 * the PIC base-register.
 * This might need to be fixed in the future or perhaps we would even want
 * pure assembly instead of inlining. ;-)
 */

#include <unistd.h>
#include <signal.h>
#include <syscall.h>

#ifdef __linux__
    #ifdef __x86_64__
        /* x86_64 performs syscalls using the syscall instruction,
         * the syscall number is stored within the RAX register
         */
        #define SET_SYSCALL "rax"
        #define ENTER_KERNEL "syscall\n"
        #define TRACY_SYSCALL_BASE (0x0)

    #elif defined(__i386__)
        /* x86 performs syscalls using the 0x80 interrupt,
         * the syscall number is stored within the EAX register
         * The tracer stores its PID in the EDI register which can then
         * be used by the child to inform the tracer of its existence.
         */
        #define SET_SYSCALL "a"
        #define INLINE_ARG0 "b"
        #define INLINE_ARG1 "c"
        #define LOAD_TRACER_PID "mov %%edi, %%ebx\n"
        #define ENTER_KERNEL "int $0x80\n"
        #define TRACY_SYSCALL_BASE (0x0)

    #elif defined(__arm__)
        /* ARM performs syscalls using the SWI instruction,
         * the syscall number is stored as part of the instruction.
         *
         * EABI defines a base to which the syscall number is added.
         * This base is statically defined in the ARM-GLibc source
         * so we should be fine.
         */
        #define SET_SYSCALL "n"
        #define ENTER_KERNEL "swi %0\n"
        /* EABI SWI_BASE */
        #define TRACY_SYSCALL_BASE (0x900000)

    #else
        #error Architecture not supported by Trampy on Linux

    #endif
#else
        #error Only Linux is currently supported by Trampy.
#endif

/* This macro inlines assembly, executing the specified
 * syscall without any arguments.
 */
#define MAKE_SYSCALL(CALL_NR) \
    __asm__( \
        ENTER_KERNEL \
        ::SET_SYSCALL( \
            TRACY_SYSCALL_BASE + CALL_NR \
        ) \
    )

/* This macro inlines a kill(2) syscall that will inform the
 * tracer of the child's existence
 *
 * LOAD_TRACER_PID executes an instruction that will copy the
 * tracer's PID from a specific register set by the tracer
 * into the first argument register of the kill(2) syscall.
 *
 * INLINE_ARG1 stores the SIGUSR1 signal value into the second argument
 * register completing kill(2)'s arguments. (ARG1 because of zero index)
 */
#define SEND_TRACER_SIGNAL() \
    __asm__( \
        LOAD_TRACER_PID \
        ENTER_KERNEL \
        ::SET_SYSCALL( \
            TRACY_SYSCALL_BASE + SYS_kill \
        ), \
        INLINE_ARG1(SIGUSR1) \
    )

/* Trampy internal declarations */
int __trampy_safe_entry(void);
static int __trampy_size_sym();

/* This function yields the size of the assembly to be injected */
size_t trampy_get_code_size(void) {
    union {
        int (*func)(void);
        size_t off;
    } start, stop;

    start.func = __trampy_safe_entry;
    stop.func = __trampy_size_sym;

    return stop.off - start.off;
}

/* This function returns a pointer to the assembly entry */
void *trampy_get_safe_entry(void) {
    union {
        int (*func)(void);
        void  *ptr;
    } _fcast;

    _fcast.func = __trampy_safe_entry;
    return _fcast.ptr;
}

/* This function is simply a container for the assembly loop
 * below, which is the actual code to be injected upon safe process
 * forking/cloning
 */
void __trampy_container_func() {
    /* Setup a label, which we can hook */
    __asm__(""\
        "__trampy_safe_entry:\n"
        );

    /* This syscall is to be replaced with the
     * appropriate fork/clone/vfork.
     */
    MAKE_SYSCALL(SYS_sched_yield);

    /* This syscall will only occur in the child as the
     * parent is restored to its original position after
     * executing the previous fork/clone/vfork syscall.
     *
     * We send the tracing process SIGUSR1 to inform it
     * of the child's existence. The tracer then attaches
     * and repositions the child to its original syscall
     * position.
     *
     * The child can obtain the PID of the tracing process
     * by reading the 4 bytes after the trampy code, that is
     * at the '__trampy_size_sym' address. The tracer will have
     * written its PID there.
     *
     * XXX: We do not do any error handling in case the kill
     * fails.
     */
    SEND_TRACER_SIGNAL();

#if 0
    /* Break stuff for libSegFault */
    __asm__("hlt\n");
#endif

    /* Now the child keeps making sched_yield syscalls until
     * the tracer restores it.
     */
    while(1) {
        MAKE_SYSCALL(SYS_sched_yield);
    }

    return;
}

/* Force alignment to 8 byte boundary to make sure
 * the reading of the PID (see comment before SYS_kill)
 * succeeds on (nearly) every architecture
 */
__asm__(".align 8");

/* This function (symbol) is used to compute
 * the size of the injected assembly */
static int __trampy_size_sym() {
    return 42;
}

