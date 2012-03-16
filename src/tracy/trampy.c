
#include <unistd.h>
#include <syscall.h>

/* x86_64 performs syscalls using the syscall instruction,
 * the syscall number is stored within the RAX register
 */
#ifdef __x86_64__
#define SET_SYSCALL "rax"
#define ENTER_KERNEL "syscall\n"
#define TRACY_SYSCALL_BASE (0x0)

/* x86 performs syscalls using the 0x80 interrupt,
 * the syscall number is stored within the EAX register
 */
#elif defined(__i386__)
#define SET_SYSCALL "a"
#define ENTER_KERNEL "int $0x80\n"
#define TRACY_SYSCALL_BASE (0x0)

/* ARM performs syscalls using the SWI instruction,
 * the syscall number is stored as part of the instruction.
 */
#elif defined(__arm__)
#define SET_SYSCALL "n"
#define ENTER_KERNEL "swi %0\n"
/* EABI SWI_BASE */
#define TRACY_SYSCALL_BASE (0x900000)

#else
#error Architecture not supported by trampy on Linux

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

/* This function (symbol) is used to compute
 * the size of the injected assembly */
static int __trampy_size_sym() {
    return 42;
}

