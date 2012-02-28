#ifndef TRACY_H
#define TRACY_H

#include <sys/wait.h>
#include "ll.h"

#define EVENT_NONE 1 << 0
#define EVENT_SYSCALL_PRE 1 << 1
#define EVENT_SYSCALL_POST 1 << 2
#define EVENT_SIGNAL 1 << 3
#define EVENT_QUIT 1 << 4

struct soxy_sc_args {
    long return_code;
    long a0, a1, a2, a3, a4, a5;
};

struct soxy_event {
    int type;
    pid_t pid;
    int syscall_num;
    long signal_num;

    struct soxy_sc_args args;
};

typedef int (*syscall_hook_func) (struct soxy_event *s);

int fork_trace_exec(int argc, char **argv);
int wait_for_syscall(struct soxy_ll *l, struct soxy_event *s);
int continue_syscall(struct soxy_event *s);
int check_syscall(struct soxy_ll *l, struct soxy_event *s);
char* get_syscall_name(int syscall);

int hook_into_syscall(struct soxy_ll *l, char *syscall, int pre, syscall_hook_func func);
int execute_hook(struct soxy_ll *ll, char *syscall, struct soxy_event *e);

int read_word(struct soxy_event *e, long from, long* word);
int read_data(struct soxy_event *e, long from, void *to, long size);

int write_word(struct soxy_event *e, long to, long word);
int write_data(struct soxy_event *e, long to, void *from, long size);

int modify_registers(struct soxy_event *e);

int inject_syscall(struct soxy_event *e);

#define OUR_PTRACE_OPTIONS (PTRACE_O_TRACESYSGOOD | PTRACE_O_TRACEFORK | \
    PTRACE_O_TRACEVFORK | PTRACE_O_TRACECLONE)


#ifdef __arm__
    #define REGS_NAME pt_regs

    /* ARM EABI puts System call number in r7 */
    #define SYSCALL_REGISTER ARM_r7

    #define SOXY_RETURN_CODE ARM_r6
    /* Missing SOXY_RETURN_CODE */

    /*
     * ARM does nasty stuff
     * http://www.arm.linux.org.uk/developer/patches/viewpatch.php?id=3105/4
     */
    #define SOXY_ARG_0 ARM_r0
    #define SOXY_ARG_1 ARM_r1
    #define SOXY_ARG_2 ARM_r2
    #define SOXY_ARG_3 ARM_r3
    #define SOXY_ARG_4 ARM_r4
    #define SOXY_ARG_5 ARM_r5

    /* Not yet used */
    #define SOXY_ARG_6 r6
#endif

#ifdef __i386__
    #define REGS_NAME user_regs_struct /* pt_regs doesn't work */

    #define SYSCALL_REGISTER orig_eax
    #define SOXY_RETURN_CODE eax
    #define SOXY_IP_REG eip

    #define SOXY_ARG_0 ebx
    #define SOXY_ARG_1 ecx
    #define SOXY_ARG_2 edx
    #define SOXY_ARG_3 esi
    #define SOXY_ARG_4 edi
    #define SOXY_ARG_5 ebp

    /* XXX: I am Linux specific and not portable.. */
    /* Linux Syscall instruction opcode (int $0x80) */
    #define TRACY_SC_MAGIC_WORD 0x000080cd

    typedef uint32_t tracy_opcode_t;
#endif

/* 'cs' determines the call type, we can use this to check if we are calling a
 * 32 bit function on 64 bit */

#ifdef __x86_64__
    #define REGS_NAME user_regs_struct /* pt_regs doesn't work */

    #define SYSCALL_REGISTER orig_rax
    #define SOXY_RETURN_CODE rax
    #define SOXY_IP_REG rip

    #define SOXY_ARG_0 rdi
    #define SOXY_ARG_1 rsi
    #define SOXY_ARG_2 rdx
    #define SOXY_ARG_3 rcx
    #define SOXY_ARG_4 r8
    #define SOXY_ARG_5 r9

    #define TRACY_SC_MAGIC_WORD 0x80;
    typedef uint64_t tracy_opcode_t;
#endif

#endif
