#ifndef TRACY_H
#define TRACY_H

#include <sys/wait.h>
#include "ll.h"

#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/user.h>

#include <asm/ptrace.h>
#include "tracyarch.h"


/* Tracy options, pass them to tracy_init(). */
#define TRACY_TRACE_CHILDREN 1 << 0

#define TRACY_USE_SAFE_TRACE 1 << 31

struct tracy_child;

struct tracy_sc_args {
    long a0, a1, a2, a3, a4, a5;
    long return_code, syscall, ip, sp;
};

struct tracy_event {
    int type;
    struct tracy_child *child;
    long syscall_num;
    long signal_num;

    struct tracy_sc_args args;
};

typedef int (*tracy_hook_func) (struct tracy_event *s);

struct tracy {
    struct soxy_ll *childs;
    struct soxy_ll *hooks;
    pid_t fpid;
    long opt;
    tracy_hook_func defhook;
};


struct tracy_inject_data {
    int injecting, injected;
    int pre;
    int syscall_num;
    struct TRACY_REGS_NAME reg;
    tracy_hook_func cb;
};

struct tracy_child {
    pid_t pid;

    /* Switch indicating we attached to this child
     *
     * Processes we attached to shouldn't be killed by default
     * since we only came along to take a peek. Childs of processes
     * attached to, should inherit this flag.
     */
    int attached;

    /* PRE/POST syscall switch */
    int pre_syscall;

    /* File descriptor pointing to /proc/<pid>/mem, -1 if closed */
    int mem_fd;

    /* Last denied syscall */
    int denied_nr;

<<<<<<< HEAD
    void* custom;

=======
    /* This child's tracy instance */
>>>>>>> 92d70abd8e8c3051a911d45e9119706f98d85153
    struct tracy* tracy;

    /* Asynchronous syscall injection info */
    struct tracy_inject_data inj;

    /* Last event that occurred */
    struct tracy_event event;

    /* Child PID acquired through controlled forking */
    pid_t safe_fork_pid;
};

/* Pointers for parent/child memory distinction */
typedef void *tracy_child_addr_t, *tracy_parent_addr_t;
<<<<<<< HEAD
=======

/* #define OUR_PTRACE_OPTIONS (PTRACE_O_TRACESYSGOOD) */
#ifdef __linux__
#define OUR_PTRACE_OPTIONS (PTRACE_O_TRACESYSGOOD | PTRACE_O_TRACEFORK | \
PTRACE_O_TRACEVFORK | PTRACE_O_TRACECLONE)
#endif

>>>>>>> 92d70abd8e8c3051a911d45e9119706f98d85153


#define TRACY_EVENT_NONE 1
#define TRACY_EVENT_SYSCALL 2
#define TRACY_EVENT_SIGNAL 3
#define TRACY_EVENT_INTERNAL 4
#define TRACY_EVENT_QUIT 5



struct tracy *tracy_init(long opt);
void tracy_free(struct tracy *t);

/* Helper */
int tracy_main(struct tracy *tracy);

/* fork_trace, returns pid */
struct tracy_child *fork_trace_exec(struct tracy *t, int argc, char **argv);
struct tracy_child *tracy_attach(struct tracy *t, pid_t pid);

/*
 * tracy_attach
 * tracy_fork
 * tracy_fork_exec
 */

/*
 * tracy_wait_event
 */
struct tracy_event *tracy_wait_event(struct tracy *t, pid_t pid);

/*
 * tracy_destroy
 */

/* -- Basic functionality -- */
int tracy_continue(struct tracy_event *s, int sigoverride);
int check_syscall(struct tracy_event *s);
char* get_syscall_name(int syscall);
char* get_signal_name(int signal);

/* -- Syscall hooks -- */
int tracy_set_hook(struct tracy *t, char *syscall, tracy_hook_func func);
int tracy_set_default_hook(struct tracy *t, tracy_hook_func f);
int tracy_execute_hook(struct tracy *t, char *syscall, struct tracy_event *e);

/* -- Child memory access -- */
int tracy_peek_word(struct tracy_child *c, long from, long* word);
ssize_t tracy_read_mem(struct tracy_child *c, tracy_parent_addr_t dest,
    tracy_child_addr_t src, size_t n);

int tracy_poke_word(struct tracy_child *c, long to, long word);
ssize_t tracy_write_mem(struct tracy_child *c, tracy_child_addr_t dest,
    tracy_parent_addr_t src, size_t n);

/* -- Child memory management -- */
int tracy_mmap(struct tracy_child *child, tracy_child_addr_t *ret,
        tracy_child_addr_t addr, size_t length, int prot, int flags, int fd,
        off_t pgoffset);
int tracy_munmap(struct tracy_child *child, long *ret,
       tracy_child_addr_t addr, size_t length);

/* -- Syscall management -- */

/* Synchronous injection */
int tracy_inject_syscall(struct tracy_child *child, long syscall_number,
        struct tracy_sc_args *a, long *return_code);

/* Asynchronous injection */
int tracy_inject_syscall_pre_start(struct tracy_child *child, long syscall_number,
        struct tracy_sc_args *a, tracy_hook_func callback);
int tracy_inject_syscall_pre_end(struct tracy_child *child, long *return_code);

int tracy_inject_syscall_post_start(struct tracy_child *child, long syscall_number,
        struct tracy_sc_args *a, tracy_hook_func callback);
int tracy_inject_syscall_post_end(struct tracy_child *child, long *return_code);

/* Modification and rejection */
int tracy_modify_syscall(struct tracy_child *child, long syscall_number,
        struct tracy_sc_args *a);
int tracy_deny_syscall(struct tracy_child* child);

/* Safe forking */
int tracy_safe_fork(struct tracy_child *c, pid_t *new_child);

#endif
