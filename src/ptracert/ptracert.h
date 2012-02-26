#ifndef PTRACERT_H
#define PTRACERT_H

#include <sys/wait.h>
#include "ll.h"

#define EVENT_NONE 1 << 0
#define EVENT_SYSCALL_PRE 1 << 1
#define EVENT_SYSCALL_POST 1 << 2
#define EVENT_SIGNAL 1 << 3
#define EVENT_QUIT 1 << 4

struct soxy_event {
    int type;
    pid_t pid;
    int syscall_num;
    long signal_num;
};

typedef int (*syscall_hook_func) (struct soxy_event *s);

int fork_trace_exec(int argc, char **argv);
int wait_for_syscall(struct soxy_ll *l, struct soxy_event *s);
int continue_syscall(struct soxy_event *s);
int check_syscall(struct soxy_ll *l, struct soxy_event *s);
char* get_syscall_name(int syscall);

int hook_into_syscall(struct soxy_ll *l, char *syscall, int pre, syscall_hook_func func);
int execute_hook(struct soxy_ll *ll, char *syscall, struct soxy_event *e);

#ifdef __arm__
    #define SYSCALL_REGISTER ARM_r7
    #define REGS_NAME pt_regs
#endif
#ifdef __i386__
    #define SYSCALL_REGISTER orig_eax
    #define REGS_NAME user_regs_struct
#endif
#ifdef __x86_64__
    #define SYSCALL_REGISTER orig_rax
    #define REGS_NAME user_regs_struct
#endif

#endif
