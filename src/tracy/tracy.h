#ifndef TRACY_H
#define TRACY_H

#include <sys/wait.h>
#include "ll.h"

struct tracy {
    struct soxy_ll *childs;
    struct soxy_ll *hooks;
    pid_t fpid;
};

struct tracy_child;

struct tracy_sc_args {
    long a0, a1, a2, a3, a4, a5;
    long return_code, syscall, ip;
};

struct tracy_event {
    int type;
    struct tracy_child *child;
    long syscall_num;
    long signal_num;

    struct tracy_sc_args args;
};

struct tracy_child {
    pid_t pid;
    int pre_syscall;
    struct tracy_event event;
};


#define TRACY_EVENT_NONE 1 << 0
#define TRACY_EVENT_SYSCALL 1 << 1
#define TRACY_EVENT_SIGNAL 1 << 2
#define TRACY_EVENT_QUIT 1 << 3


typedef int (*tracy_hook_func) (struct tracy_event *s);


struct tracy *tracy_init(void);
void tracy_free(struct tracy *t);

/* fork_trace, returns pid */
struct tracy_child *fork_trace_exec(struct tracy *t, int argc, char **argv);

/*
 * tracy_attach
 * tracy_fork
 * tracy_fork_exec
 */

/*
 * tracy_wait_event
 */
struct tracy_event *tracy_wait_event(struct tracy *t);

/*
 * tracy_destroy
 */

int tracy_continue(struct tracy_event *s);
int check_syscall(struct tracy_event *s);
char* get_syscall_name(int syscall);

int tracy_set_hook(struct tracy *t, char *syscall, tracy_hook_func func);
int tracy_execute_hook(struct tracy *t, char *syscall, struct tracy_event *e);

#if 0
int read_word(struct tracy_event *e, long from, long* word);
int read_data(struct tracy_event *e, long from, void *to, long size);

int write_word(struct tracy_event *e, long to, long word);
int write_data(struct tracy_event *e, long to, void *from, long size);
#endif

int modify_registers(struct tracy_event *e);

int tracy_inject_syscall(struct tracy_event *e);
int tracy_inject_syscall_pre(struct tracy_event *e);
int tracy_inject_syscall_post(struct tracy_event *e);
int tracy_change_syscall();
int tracy_deny_syscall();

#define OUR_PTRACE_OPTIONS (PTRACE_O_TRACESYSGOOD | PTRACE_O_TRACEFORK | \
    PTRACE_O_TRACEVFORK | PTRACE_O_TRACECLONE)


#ifdef __arm__
    #define TRACY_REGS_NAME pt_regs

    /* Unsure about some of the registers */
    #define TRACY_SYSCALL_OPSIZE 8

    /* ARM EABI puts System call number in r7 */
    #define TRACY_SYSCALL_REGISTER ARM_r7
    #define TRACY_SYSCALL_N ARM_r8

    #define TRACY_RETURN_CODE ARM_r6

    #define TRACY_IP_REG ARM_pc

    /*
     * ARM does nasty stuff
     * http://www.arm.linux.org.uk/developer/patches/viewpatch.php?id=3105/4
     */
    #define TRACY_ARG_0 ARM_r0
    #define TRACY_ARG_1 ARM_r1
    #define TRACY_ARG_2 ARM_r2
    #define TRACY_ARG_3 ARM_r3
    #define TRACY_ARG_4 ARM_r4
    #define TRACY_ARG_5 ARM_r5
#endif

#ifdef __i386__
    #define TRACY_REGS_NAME user_regs_struct /* pt_regs doesn't work */

    #define TRACY_SYSCALL_OPSIZE 2

    #define TRACY_SYSCALL_REGISTER orig_eax
    #define TRACY_SYSCALL_N eax

    #define TRACY_RETURN_CODE eax
    #define TRACY_IP_REG eip

    #define TRACY_ARG_0 ebx
    #define TRACY_ARG_1 ecx
    #define TRACY_ARG_2 edx
    #define TRACY_ARG_3 esi
    #define TRACY_ARG_4 edi
    #define TRACY_ARG_5 ebp

    typedef uint32_t tracy_opcode_t;
#endif

/* 'cs' determines the call type, we can use this to check if we are calling a
 * 32 bit function on 64 bit */

#ifdef __x86_64__
    #define TRACY_REGS_NAME user_regs_struct /* pt_regs doesn't work */

    #define TRACY_SYSCALL_OPSIZE 2

    #define TRACY_SYSCALL_REGISTER orig_rax
    #define TRACY_SYSCALL_N rax

    #define TRACY_RETURN_CODE rax
    #define TRACY_IP_REG rip

    #define TRACY_ARG_0 rdi
    #define TRACY_ARG_1 rsi
    #define TRACY_ARG_2 rdx
    #define TRACY_ARG_3 rcx
    #define TRACY_ARG_4 r8
    #define TRACY_ARG_5 r9

    typedef uint64_t tracy_opcode_t;
#endif

#endif
