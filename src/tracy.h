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
#ifndef TRACY_H
#define TRACY_H

#include <stdio.h>
#include <sys/wait.h>
#include "ll.h"

#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/user.h>

#include <asm/ptrace.h>
#include "tracyarch.h"

#include <signal.h>


/* Possible directives:
 *
 * - TRACY_DELIVER_SIGTRAP:
 *   Pass along a SIGTRAP signal if it doesn't seem to come from the kernel, in
 *   other words, send along SIGTRAP signals to tracees if they'd kill()
 *   themselves with SIGTRAP.
 */

#if 0
#define TRACY_DELIVER_SIGTRAP
#endif

/* Tracy options, pass them to tracy_init(). */
#define TRACY_TRACE_CHILDREN (1 << 0)
#define TRACY_VERBOSE (1 << 1)
#define TRACY_VERBOSE_SIGNAL (1 << 2)
#define TRACY_VERBOSE_SYSCALL (1 << 3)

/* Enable automatic usage of ptrace's memory API when PPM (/proc based) fails */
#define TRACY_MEMORY_FALLBACK (1 << 4)

#define TRACY_USE_SAFE_TRACE (1 << 31)

#define TRACY_PRINT_SIGNALS(t) \
        ((t)->opt & TRACY_VERBOSE_SIGNAL)
#define TRACY_PRINT_SYSCALLS(t) \
        ((t)->opt & TRACY_VERBOSE_SYSCALL)

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

    long abi;

    struct tracy_sc_args args;
    siginfo_t siginfo;
};

typedef int (*tracy_hook_func) (struct tracy_event *s);

typedef void (*tracy_child_creation) (struct tracy_child *c);

struct tracy_abi_syscall {
    char *name;
    int call_nr;
};

/*
 * Special events. A set of functions to be called when certain things
 * happen. Currently contains:
 *
 * child_create(tracy_child *c);
 *
 *      To be used to initialise some values when a child is created.
 *      You cannot inject anything at this time and you shall not touch the
 *      event variable of the child.
 *
 *      If you want to mess with system calls and injection, simply wait for the
 *      first event of the child; as this will always be called before you
 *      recieve an event from the new child.
 *
 */
struct tracy_special_events {
    tracy_child_creation child_create;
};

struct tracy {
    struct tracy_ll *childs;
    struct tracy_ll *hooks;
    pid_t fpid;
    long opt;
    tracy_hook_func defhook;
    tracy_hook_func signal_hook;
    struct tracy_special_events se;
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

    /* Fallback indicator used in case /proc access fails */
    int mem_fallback;

    /* Last denied syscall */
    int denied_nr;

    /* Suppress next signal on tracy_continue */
    int suppress;

    /* User data passed to the hooks */
    void* custom;

    /* This child's tracy instance */
    struct tracy* tracy;

    /* Asynchronous syscall injection info */
    struct tracy_inject_data inj;

    /* Child in vfork parent-role (frozen until child execve, etc.) */
    int frozen_by_vfork;

    /* If the child has recieved the first SIGSTOP (that we will block) */
    int received_first_sigstop;

    /* vfork restoration values */
    long orig_pc;
    long orig_trampy_pid_reg;
    long orig_return_code;

    /* Last event that occurred */
    struct tracy_event event;
};

/* Pointers for parent/child memory distinction */
typedef void *tracy_child_addr_t, *tracy_parent_addr_t;

/* The various tracy events */
#define TRACY_EVENT_NONE 0 /* This should be zero because none_event is nulled */
#define TRACY_EVENT_SYSCALL 1
#define TRACY_EVENT_SIGNAL 2
#define TRACY_EVENT_INTERNAL 3
#define TRACY_EVENT_QUIT 4

/* Define hook return values */
#define TRACY_HOOK_CONTINUE 0
#define TRACY_HOOK_KILL_CHILD 1
#define TRACY_HOOK_ABORT 2
#define TRACY_HOOK_NOHOOK 3
#define TRACY_HOOK_SUPPRESS 4
#define TRACY_HOOK_DENY 5

/* Setting up and tearing down a tracy session */

/*
 * tracy_init
 *
 * tracy_init creates the tracy record and returns a pointer to this record on
 * success. Possible options for ``opt'':
 *
 *  -   TRACY_TRACE_CHILDREN (Trace children of the tracee created with fork,
 *      vfork or clone.)
 *
 *  -   TRACY_USE_SAFE_TRACE (Do not rely on Linux' auto-trace on fork abilities
 *      and instead use our own safe implementation)
 *
 *      This option is still experimental.
 *
 * Returns the tracy record created.
 */
struct tracy *tracy_init(long opt);

/*
 * tracy_free
 *
 * tracy_free frees all the data associated with tracy:
 * -    Any children being traced are either detached (if we attached) or killed
 *      if tracy started them
 * -    Datastructures used internally.
 *
 */
void tracy_free(struct tracy *t);

/*
 * tracy_quit
 *
 * tracy_quit frees all the structures, kills or detaches from all the
 * children and then calls exit() with *exitcode*. Use tracy_free if you want to
 * gracefully free tracy.
 *
 */

void tracy_quit(struct tracy* t, int exitcode);

/*
 * tracy_main
 *
 * tracy_main is a simple tracy-event loop.
 * Helper for RAD Tracy deployment
 *
 */
int tracy_main(struct tracy *tracy);

/*
 * tracy_exec
 *
 * tracy_exec is the function tracy offers to actually start tracing a
 * process. tracy_exec safely forks, asks to be traced in the child and
 * then executes the given process with possible arguments.
 *
 * Returns the first tracy_child. You don't really need to store this as each
 * event will be directly coupled to a child.
 */
struct tracy_child *tracy_exec(struct tracy *t, char **argv);

/*
 * tracy_attach
 *
 * tracy_attach attaches to a running process specified by pid.
 *
 * Returns the structure of the attached child.
 */
struct tracy_child *tracy_attach(struct tracy *t, pid_t pid);

/*
 * tracy_add_child
 *
 * tracy_add_child adds a child to tracy's list of children.
 *
 * Returns the structure of the child.
 */
struct tracy_child * tracy_add_child(struct tracy *t, int pid);

/*
 * tracy_wait_event
 *
 * tracy_wait_event waits for an event to occur on any child when pid is -1;
 * else on a specific child.
 *
 * tracy_wait_event will detect any new children and automatically add them to
 * the appropriate datastructures.
 *
 * An ``event'' is either a signal or a system call. tracy_wait_event populates
 * events with the right data; arguments; system call number, etc.
 *
 * Returns an event pointer or NULL.
 *
 * If NULL is returned, you should probably kill all the children and stop
 * tracy; NULL indicates something went wrong internally such as the inability
 * to allocate memory or an unsolvable ptrace error.
 */
struct tracy_event *tracy_wait_event(struct tracy *t, pid_t pid);

/* -- Basic functionality -- */

/*
 * tracy_continue
 *
 * tracy_continue continues the execution of the child that owns event *s*.
 * If the event was caused by a signal to the child, the signal
 * is passed along to the child, unless *sigoverride* is set to nonzero.
 *
 */
int tracy_continue(struct tracy_event *s, int sigoverride);

/*
 * tracy_kill_child
 *
 * tracy_kill_child attemps to kill the child *c*; it does so using ptrace with
 * the PTRACE_KILL argument.
 *
 * Return 0 upon success, -1 upon failure.
 */
int tracy_kill_child(struct tracy_child *c);

int tracy_remove_child(struct tracy_child *c);

/*
 * tracy_children_count
 *
 * tracy_children_count returns the amount of alive children managed by tracy.
 */
int tracy_children_count(struct tracy* t);

#if 0
char* get_syscall_name(int syscall);
int get_syscall_number(const char *syscall);
#endif

char* get_syscall_name_abi(int syscall, int abi);
int get_syscall_number_abi(const char *syscall, int abi);

char* get_signal_name(int signal);

/* -- Syscall hooks -- */
/*
 * tracy_set_hook
 *
 * Set the hook for a system call with the given ABI. If you want
 * to hook a system call on multiple ABIs, you need to call
 * tracy_set_hook for each ABI.
 *
 * Returns 0 on success, -1 on failure.
 */

int tracy_set_hook(struct tracy *t, char *syscall, long abi, tracy_hook_func func);

/*
 * tracy_set_signal_hook
 *
 * Set the signal hook. Called on each signal[1].
 *
 * Returns 0 on success.
 *
 * [1] Called on every signal that the tracy user should recieve,
 * the SIGTRAP's from ptrace are not sent, and neither is the first
 * SIGSTOP.
 * Possible return values by the tracy_hook_func for the signal:
 *
 *  -   TRACY_HOOK_CONTINUE will send the signal and proceed as normal
 *  -   TRACY_HOOK_SUPPRESS will not send a signal and process as normal
 *  -   TRACY_HOOK_KILL_CHILD if the child should be killed.
 *  -   TRACY_HOOK_ABORT if tracy should kill all childs and quit.
 *
 */
int tracy_set_signal_hook(struct tracy *t, tracy_hook_func f);
/*
 * tracy_set_default_hook
 *
 * Set the default hook. (Called when a syscall occurs and no hook is installed
 * for the system call. *func* is the function to be set as hook.
 *
 * Returns 0 on success.
 */
int tracy_set_default_hook(struct tracy *t, tracy_hook_func f);

/*
 * tracy_execute_hook
 *
 *
 * Returns the return value of the hook. Hooks should return:
 *
 *  -   TRACY_HOOK_CONTINUE if everything is fine.
 *  -   TRACY_HOOK_KILL_CHILD if the child should be killed.
 *  -   TRACY_HOOK_ABORT if tracy should kill all childs and quit.
 *  -   TRACY_HOOK_NOHOOK is no hook is in place for this system call.
 *
 */
int tracy_execute_hook(struct tracy *t, char *syscall, struct tracy_event *e);

/* -- Child memory access -- */
ssize_t tracy_read_mem(struct tracy_child *c, tracy_parent_addr_t dest,
    tracy_child_addr_t src, size_t n);
char* tracy_read_string(struct tracy_child *c, tracy_child_addr_t src);

ssize_t tracy_write_mem(struct tracy_child *c, tracy_child_addr_t dest,
    tracy_parent_addr_t src, size_t n);

/* -- Child memory management -- */
int tracy_mmap(struct tracy_child *child, tracy_child_addr_t *ret,
        tracy_child_addr_t addr, size_t length, int prot, int flags, int fd,
        off_t pgoffset);
int tracy_munmap(struct tracy_child *child, long *ret,
       tracy_child_addr_t addr, size_t length);

/* -- Debug functions -- */
int tracy_debug_current(struct tracy_child *child);
void tracy_backtrace(void);

/* Synchronous injection */
int tracy_inject_syscall(struct tracy_child *child, long syscall_number,
        struct tracy_sc_args *a, long *return_code);

/* Asynchronous injection */
int tracy_inject_syscall_async(struct tracy_child *child, long syscall_number,
        struct tracy_sc_args *a, tracy_hook_func callback);

/* These should be used interally only */
int tracy_inject_syscall_pre_start(struct tracy_child *child, long syscall_number,
        struct tracy_sc_args *a, tracy_hook_func callback);
int tracy_inject_syscall_pre_end(struct tracy_child *child, long *return_code);

int tracy_inject_syscall_post_start(struct tracy_child *child, long syscall_number,
        struct tracy_sc_args *a, tracy_hook_func callback);
int tracy_inject_syscall_post_end(struct tracy_child *child, long *return_code);

/* Modification and rejection */
int tracy_modify_syscall_args(struct tracy_child *child, long syscall_number,
        struct tracy_sc_args *a);
int tracy_modify_syscall_regs(struct tracy_child *child, long syscall_number,
        struct tracy_sc_args *a);
int tracy_deny_syscall(struct tracy_child* child);

/* -- Safe forking -- */
int tracy_safe_fork(struct tracy_child *c, pid_t *new_child);

/* Tracy W^X */

/* -- Macro's -- */

/* Coloured output */
#ifndef GRIJSKIJKER
#define _r(s) "\033[1;31m" s "\033[0m"
#define _g(s) "\033[1;32m" s "\033[0m"
#define _y(s) "\033[1;33m" s "\033[0m"
#define _b(s) "\033[1;34m" s "\033[0m"
#else
#define _r(s) s
#define _g(s) s
#define _y(s) s
#define _b(s) s
#endif

/* Automatic error handling/debugging for ptrace(2) */
#define _PTRACE_CHECK(A1, S1, A2, A3, A4, A5) \
    { \
        if (ptrace(A1, A2, A3, A4)) { \
            printf("\n-------------------------------" \
                    "-------------------------------------------------\n"); \
            perror("Whoops"); \
            printf("Function: %s, File: %s, Line: %d\n", __FUNCTION__, __FILE__, __LINE__); \
            printf("Arguments: %s, %s (%d), %s, %s\n", S1, #A2, A2, #A3, #A4); \
            printf("-------------------------------" \
                    "-------------------------------------------------\n"); \
            tracy_backtrace(); \
            A5 \
        } \
    }

#define PTRACE_CHECK(A1, A2, A3, A4, A5) _PTRACE_CHECK(A1, #A1, A2, A3, A4, return A5;)

#define PTRACE_CHECK_NORETURN(A1, A2, A3, A4) _PTRACE_CHECK(A1, #A1, A2, A3, A4, ;)

/* For all the casts we should be punished for
 *
 * The FORCE_CAST unconditionally stores the value of the source-var with
 * source-type into the variable dest-var of dest-type.
 */
#define FORCE_CAST(DEST_TYPE, DEST_VAR, SRC_TYPE, SRC_VAR) \
    { \
        union { \
            SRC_TYPE src_type; \
            DEST_TYPE dest_type; \
        } _force_cast_ ## __LINE__; \
        _force_cast_ ## __LINE__.src_type = SRC_VAR; \
        DEST_VAR = _force_cast_ ## __LINE__.dest_type; \
    }


#define SYSCALL_FROM_EVENT(event) \
( \
    get_syscall_name_abi(event->syscall_num, event->abi) \
)

/* TODO XXX FIXME: What is get_syscall_name returns NULL? */
#define EVENT_IS_SYSCALL(event, syscall) \
{ \
    strcmp(SYSCALL_NAME_FROM_EVENT(event), syscall) == 0; \
}
#endif
