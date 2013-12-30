/*
    This file is part of Tracy.

    Tracy is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    Tracy is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with Tracy.  If not, see <http://www.gnu.org/licenses/>.
*/

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
        #define SET_SYSCALL "i"
        #define INLINE_ARG0 "i"
        #define INLINE_ARG1 "i"
        #define LOAD_TRACER_PID \
            "mov %1, %%rsi\n" \
            "mov %%r8, %%rdi\n"
        #define ENTER_KERNEL \
            "mov %0, %%rax\n" \
            "syscall\n"
    
    #elif defined(__i386__)
        /* x86 performs syscalls using the 0x80 interrupt,
         * the syscall number is stored within the EAX register
         * The tracer stores its PID in the EDI register which can then
         * be used by the child to inform the tracer of its existence.
         */
        #define SET_SYSCALL "a"
        #define INLINE_ARG0 "b"
        #define INLINE_ARG1 "c"
        #define LOAD_TRACER_PID "mov %%ebp, %%ebx\n"
        #define ENTER_KERNEL "int $0x80\n"

    #elif defined(__arm__)
        /* ARM performs syscalls using the SWI instruction,
         * on ARM there are to ABIs the old (OABI), and the new
         * (EABI), in the OABI the syscall number is stored as part
         * of the instruction. In EABI the instruction part is set
         * to 1, aka "restart_syscall", and the actual syscall number
         * is stored in register 'r7'.
         *
         * Furthermore OABI defines a base to which the syscall number
         * is added. This base is statically defined in the ARM-GLibc source
         * so we should be fine.
         *
         * Trampy kills two birds with one stone by setting the instruction
         * part to the correct OABI value and storing the EABI syscall
         * value in r7, theoretically Trampy should work without change
         * on OABI and EABI.
         */
        #define SET_SYSCALL(VAL) \
            "n"(VAL + TRACY_SWI_BASE), \
            "n"(VAL)
        #define INLINE_ARG0 "b"
        #define INLINE_ARG1 "i"
        /* On ARM, since we cannot load into specific registers,
         * we have to cheat a little by also loading the signal
         * number during the LOAD_TRACER_PID command.
         */
        #define LOAD_TRACER_PID \
            "mov r0, r4\n" \
            "mov r1, %2\n"
        #define ENTER_KERNEL \
            "mov r7, %1\n" \
            "swi %0\n"
        /* OABI SWI_BASE */
        #define TRACY_SWI_BASE (0x900000)
    #elif defined(__powerpc__)
        /* On powerpc the syscall number is stored in r0,
         * the arguments in r3-r9 we use r30 for the storing of the pid
         */
        #define SET_SYSCALL "i"
        #define INLINE_ARG0 "i"
        #define INLINE_ARG1 "i"
        #define LOAD_TRACER_PID "li 31, %1\n"
        #define ENTER_KERNEL \
                "li 0, %0\n" \
                "sc\n"
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
        ::SET_SYSCALL(CALL_NR) \
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
        ::SET_SYSCALL(SYS_kill), \
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
     * by reading a specific register. The tracer will have
     * written its PID there. To find out which register, see
     * the macro's at the start of the Trampy file.
     *
     * XXX: We do not do any error handling in case the kill
     * fails.
     */
    SEND_TRACER_SIGNAL();

#if 0
    /* Break stuff for libSegFault */
    #ifdef __arm__
    __asm__("mov pc, #0\n");
    #elif defined(__i386__) || defined(__x86_64__)
    __asm__("hlt\n");
    #endif
#endif

    /* Now the child keeps making sched_yield syscalls until
     * the tracer restores it.
     */
    while(1) {
        MAKE_SYSCALL(SYS_sched_yield);
    }

    return;
}

/* This function (symbol) is used to compute
 * the size of the injected assembly */
static int __trampy_size_sym() {
    return 42;
}

