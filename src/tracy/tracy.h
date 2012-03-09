#ifndef TRACY_H
#define TRACY_H

#include <sys/wait.h>
#include "ll.h"

#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/user.h>

#include <asm/ptrace.h>
#include "tracyarch.h"

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

typedef int (*tracy_hook_func) (struct tracy_event *s);

struct tracy_inject_data {
    int injecting, injected;
    int pre;
    struct TRACY_REGS_NAME reg;
    tracy_hook_func cb;
};

struct tracy_child {
    pid_t pid;
    int pre_syscall;
    struct tracy_event event;
    int mem_fd;

    struct tracy_inject_data inj;
};


#define TRACY_EVENT_NONE 1 << 0
#define TRACY_EVENT_SYSCALL 1 << 1
#define TRACY_EVENT_SIGNAL 1 << 2
#define TRACY_EVENT_QUIT 1 << 3



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

/* Basic functionality */
int tracy_continue(struct tracy_event *s);
int check_syscall(struct tracy_event *s);
char* get_syscall_name(int syscall);

/* Syscall hooks */
int tracy_set_hook(struct tracy *t, char *syscall, tracy_hook_func func);
int tracy_execute_hook(struct tracy *t, char *syscall, struct tracy_event *e);

/* Child memory access */
int tracy_peek_word(struct tracy_child *c, long from, long* word);
ssize_t tracy_read_mem(struct tracy_child *c, void *dest, void *src, size_t n);

int tracy_poke_word(struct tracy_child *c, long to, long word);
ssize_t tracy_write_mem(struct tracy_child *c, void *dest, void *src, size_t n);

/* Syscall modification and injection */
int modify_registers(struct tracy_event *e);

int tracy_inject_syscall(struct tracy_child *child, long syscall_number,
        struct tracy_sc_args *a, long *return_code);

/*
int tracy_inject_syscall_pre(struct tracy_child *child, long syscall_number,
        struct tracy_sc_args *a, int *return_code);
*/

int tracy_inject_syscall_pre_pre(struct tracy_child *child, long syscall_number,
        struct tracy_sc_args *a, tracy_hook_func callback);
int tracy_inject_syscall_pre_post(struct tracy_child *child, long *return_code);

int tracy_inject_syscall_post_pre(struct tracy_child *child, long syscall_number,
        struct tracy_sc_args *a, tracy_hook_func callback);
int tracy_inject_syscall_post_post(struct tracy_child *child, long *return_code);

/*
int tracy_inject_syscall_post(struct tracy_child *child, long syscall_number,
        struct tracy_sc_args *a, long *return_code);
*/
int tracy_change_syscall();
int tracy_deny_syscall();

#endif
