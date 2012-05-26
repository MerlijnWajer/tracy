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
/*
 * tracy.c: ptrace convenience library
 *
 * TODO:
 *  -   Define and harden async API.
 *  -   Write test cases
 *  -   Replace ll with a better datastructure.
 */
#include <inttypes.h>

#include <sys/stat.h>
#include <fcntl.h>

#include <stdint.h>
#include <unistd.h>

#include <sys/wait.h>
#include <signal.h>

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>

#include <string.h>

#include <sys/syscall.h>

#include <sys/mman.h>

#include "ll.h"
#include "tracy.h"
#include "trampy.h"

#include <execinfo.h>

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

/* Macro's */
#define PTRACE_CHECK(A1, A2, A3, A4, A5) \
    { \
        if (ptrace(A1, A2, A3, A4)) { \
            printf("\n-------------------------------" \
                    "-------------------------------------------------\n"); \
            perror("Whoops"); \
            printf("Function: %s, Line: %d\n", __FUNCTION__, __LINE__); \
            printf("Arguments: %s, %s, %s, %s\n", #A1, #A2, #A3, #A4); \
            printf("-------------------------------" \
                    "-------------------------------------------------\n"); \
            return A5; \
        } \
    }

struct tracy *tracy_init(long opt) {
    struct tracy *t;

    t = malloc(sizeof(struct tracy));

    if (!t) {
        return NULL;
    }

    t->fpid = 0;

    t->childs = ll_init();
    t->hooks = ll_init();

    if (!t->childs || !t->hooks) {
        free(t->childs);
        free(t->hooks);
        free(t);
        return NULL;
    }

    /* TODO Check opt for validity */
    t->opt = opt;

    t->se.child_create = NULL;

    return t;
}

/* Loop over all child structs in the children list and free them */
static void free_children(struct soxy_ll *children)
{
    struct tracy_child *tc;
    struct soxy_ll_item *cur = children->head;

    /* Walk over all items in the list */
    while(cur) {
        tc = cur->data;

        /* Detach or kill */
        if (tc->attached) {
            fprintf(stderr, _b("Detaching from child %d")"\n", tc->pid);
            ptrace(PTRACE_DETACH, tc->pid, NULL, NULL);
            /* TODO: Check return value? */

        } else {
            /* This works because PTRACE_KILL is the only call that allows a
             * child not to be stopped at the time of the ptrace call:
             *
             *   The  above  request is used only by the child process; the
             *   rest are used only by the parent.  In the following requests,
             *   pid specifies the child process to be acted on.
             *   For requests other than PTRACE_KILL,
             *   the child process must be stopped.
             */
            fprintf(stderr, _b("Killing child %d")"\n", tc->pid);
            ptrace(PTRACE_KILL, tc->pid, NULL, NULL);
            /* TODO: Check value
             * TODO: PTRACE_KILL is deprecated, use tracy_kill_child instead?
             */
        }

        /* Free data and fetch next item */
        free(tc);
        cur = cur->next;
    }

    return;
}

void tracy_free(struct tracy* t) {
    /* Free hooks list */
    ll_free(t->hooks);

    /* Free all children */
    free_children(t->childs);
    ll_free(t->childs);

    free(t);
}

void tracy_quit(struct tracy* t, int exitcode) {
    tracy_free(t);
    exit(exitcode);
}

static struct tracy_child *malloc_tracy_child(struct tracy *t, pid_t pid)
{
    struct tracy_child *tc;

    /* Tracy non-null pointer? */
    if (!t) {
        errno = EINVAL;
        return NULL;
    }

    tc = malloc(sizeof(struct tracy_child));
    if (!tc)
        return NULL;

    tc->attached = 0;
    tc->mem_fd = -1;
    tc->mem_fallback = 0;
    tc->pid = pid;
    tc->pre_syscall = 0;
    tc->inj.injecting = 0;
    tc->inj.cb = NULL;
    tc->denied_nr = 0;
    tc->tracy = t;
    tc->custom = NULL;

    return tc;
}

/* TODO: Environment variables? */
struct tracy_child* fork_trace_exec(struct tracy *t, int argc, char **argv) {
    pid_t pid;
    long r;
    int status;
    /* TRACESYSGOOD is default for now. BSD doesn't have this... */
    long ptrace_options = PTRACE_O_TRACESYSGOOD;
    long signal_id;
    struct tracy_child *tc;

    if ((t->opt & TRACY_TRACE_CHILDREN) && !(t->opt & TRACY_USE_SAFE_TRACE)) {
        /* XXX: None of this is available on BSD.
         * So if at some point we are going to rely on these events, we should
         * mimic them on BSD. I suggest not relying on them and just using our
         * own internal call.
         *
         * The only important ptrace option is PTRACE_O_TRACESYSGOOD, which we
         * use simply for performance reasons.
         *
         * All the non-process creation extra options are used only for clarity
         * when we are sent a SIGTRAP.
         *
         * Eventually, we should replace the process-creation options with our
         * own equivalent (safe-fork). When that happens, we could remove all
         * these extra options and implement something that works on BSD as
         * well, at least theoretically.
         */
        ptrace_options |= PTRACE_O_TRACEFORK;
        ptrace_options |= PTRACE_O_TRACEVFORK;
        ptrace_options |= PTRACE_O_TRACECLONE;
        ptrace_options |= PTRACE_O_TRACEEXIT;
        ptrace_options |= PTRACE_O_TRACEEXEC;
        ptrace_options |= PTRACE_O_TRACEVFORKDONE;
    }

    pid = fork();

    /* Child */
    if (pid == 0) {
        r = ptrace(PTRACE_TRACEME, 0, NULL, NULL);
        if (r) {
            /* TODO: Failure */
        }

        /* Give the parent to chance to set some extra tracing options before we
         * restart the child and let it call exec() */
        raise(SIGTRAP);

        if (argc == 1) {
            execv(argv[0], argv);
        } else {
            execv(argv[0], argv);
        }

        if (errno == -1) {
            /* TODO: Failure */
        }
    }

    if (pid == -1)
        return NULL;

    /* Parent */
    if (t->fpid == 0)
        t->fpid = pid;

    /* Wait for SIGTRAP from the child */
    waitpid(pid, &status, 0);

    signal_id = WSTOPSIG(status);
    if (signal_id != SIGTRAP) {
        /* TODO: Failure */
        ptrace(PTRACE_KILL, pid, NULL, NULL);
        /* TODO: PTRACE_KILL is deprecated, use tracy_kill_child? */
    }

    r = ptrace(PTRACE_SETOPTIONS, pid, NULL, (void*)ptrace_options);
    if (r) {
        ptrace(PTRACE_KILL, pid, NULL, NULL);
        /* TODO: PTRACE_KILL is deprecated, use tracy_kill_child? */
        /* TODO: Options may not be supported... Linux 2.4? */
    }

    /* We have made sure we will trace each system call of the child, including
     * the system calls of the children of the child, so the child can now
     * resume. */
    r = ptrace(PTRACE_SYSCALL, pid, NULL, 0);
    if (r) {
        ptrace(PTRACE_KILL, pid, NULL, NULL);
        /* TODO: PTRACE_KILL is deprecated, use tracy_kill_child? */
        return NULL;
    }

    tc = malloc_tracy_child(t, pid);
    if (!tc) {
        ptrace(PTRACE_KILL, pid, NULL, NULL);
        /* TODO: PTRACE_KILL is deprecated, use tracy_kill_child? */
        return NULL;
    }

    ll_add(t->childs, tc->pid, tc);
    if (t->se.child_create)
        (t->se.child_create)(tc);

    return tc;
}

/* Attach to a process for tracing
 * Upon failure returns: NULL.
 *
 * 'errno' will be set appropriately.
 */
struct tracy_child *tracy_attach(struct tracy *t, pid_t pid)
{
    long r;
    int status;
    /* TRACESYSGOOD is default for now. BSD doesn't have this... */
    long ptrace_options = PTRACE_O_TRACESYSGOOD;
    long signal_id;
    struct tracy_child *tc;

    if ((t->opt & TRACY_TRACE_CHILDREN) && !(t->opt & TRACY_USE_SAFE_TRACE)) {
        ptrace_options |= PTRACE_O_TRACEFORK;
        ptrace_options |= PTRACE_O_TRACEVFORK;
        ptrace_options |= PTRACE_O_TRACECLONE;
    }

    PTRACE_CHECK(PTRACE_ATTACH, pid, NULL, NULL, NULL);

    tc = malloc(sizeof(struct tracy_child));
    if (!tc) {
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
        return NULL;
    }

    /* Parent */

    if (t->fpid == 0)
        t->fpid = pid;

    /* Wait for SIGSTOP from the child */
    waitpid(pid, &status, 0);

    signal_id = WSTOPSIG(status);
    if (signal_id != SIGSTOP && signal_id != SIGTRAP) {
        fprintf(stderr, "tracy: Error: No SIG(STOP|TRAP), got %s (%ld)\n",
            get_signal_name(signal_id), signal_id);
        /* TODO: Failure */
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
        /* XXX: Need to set errno to something useful */
        return NULL;
    }

    r = ptrace(PTRACE_SETOPTIONS, pid, NULL, (void*)ptrace_options);
    if (r) {
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
        /* TODO: Options may not be supported... Linux 2.4? */
        return NULL;
    }

    /* We have made sure we will trace each system call of the child, including
     * the system calls of the children of the child, so the child can now
     * resume. */
    r = ptrace(PTRACE_SYSCALL, pid, NULL, 0);
    if (r) {
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
        return NULL;
    }

    tc = malloc_tracy_child(t, pid);
    if (!tc) {
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
        return NULL;
    }

    /* This is an attached child */
    tc->attached = 1;

    ll_add(t->childs, tc->pid, tc);

    /* TODO: Special event for attached child? */
    if (t->se.child_create)
        (t->se.child_create)(tc);
    return tc;

}

static int _tracy_handle_injection(struct tracy_event *e) {
    tracy_hook_func f;

    if (e->child->inj.pre) {
        /* TODO: This probably shouldn't be args.return_code as we're
         * messing with the arguments of the original system call */
        tracy_inject_syscall_pre_end(e->child, &e->args.return_code);
    } else {
        /* TODO: This probably shouldn't be args.return_code as we're
         * messing with the arguments of the original system call */
        tracy_inject_syscall_post_end(e->child, &e->args.return_code);
    }

    e->child->inj.injecting = 0;
    e->child->inj.injected = 1;
    f = e->child->inj.cb;
    e->child->inj.cb = NULL;
    if (f)
        f(e);
    e->child->inj.injected = 0;

    return 0;
}

static struct tracy_event none_event = {
        TRACY_EVENT_NONE, NULL, 0, 0,
        {0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
    };

/*
 * tracy_wait_event returns an event that is either an event belonging to a
 * child (already allocated) or the none_event (which is also already
 * allocated).
 */
/* TODO: Check if the pid is any of our children? Or will waitpid already return
 * an error? */
struct tracy_event *tracy_wait_event(struct tracy *t, pid_t c_pid) {
    int status, savedstatus, signal_id, info;
    siginfo_t siginfo;
    pid_t pid;
    struct TRACY_REGS_NAME regs;
    struct tracy_child *tc;
    struct tracy_event *s;
    struct soxy_ll_item *item;

    s = NULL;

    /* Wait for changes */
    pid = waitpid(c_pid, &status, __WALL);
    savedstatus = status;

    /* Something went wrong. */
    if (pid == -1) {
        if (errno == EINTR) {
            return NULL;
        }

        /* If we were not interrupted, we no longer have any children. */
        return &none_event;
    }

    if (pid != -1) {
        item = ll_find(t->childs, pid);
        if (!item) {
            if (t->opt & TRACY_VERBOSE)
                printf(_y("New child: %d. Adding to tracy...")"\n", pid);
            tc = malloc_tracy_child(t, pid);
            if (!tc) {
                perror("Cannot allocate structure for new child");
                return NULL; /* TODO Kill the child ? */
            }

            /* TODO: Determine if parent was attached to or created by us,
             * and set tc->attached appropriately.
             */

            ll_add(t->childs, tc->pid, tc);

            if (t->se.child_create)
                (t->se.child_create)(tc);

            s = &tc->event;
            s->child = tc;
        } else {
            s = &(((struct tracy_child*)(item->data))->event);
            s->child = item->data;
        }
    }

    /* Do we want this before the signal checks? Will do for now */
    if(s->child->inj.injecting) {
        /* We don't want to touch the event if we're injecting a system call */
        if (!_tracy_handle_injection(s)) {
            s->type = TRACY_EVENT_INTERNAL;
            s->syscall_num = s->child->inj.syscall_num;
            return s;
        }
    }

    s->type = 0;
    s->syscall_num = 0;
    s->signal_num = 0;

    if (!WIFSTOPPED(status)) {
        s->type = TRACY_EVENT_QUIT;
        if (WIFEXITED(status)) {
            s->signal_num = WEXITSTATUS(status);
        } else if (WIFSIGNALED(status)) {
            s->signal_num = WTERMSIG(status); /* + 128 */
        } else {
            if (t->opt & TRACY_VERBOSE)
                puts(_y("Recursing due to WIFSTOPPED"));
            return tracy_wait_event(t, c_pid);
        }
        return s;
    }

    signal_id = WSTOPSIG(status);

    if (signal_id == (SIGTRAP | 0x80)) {
        /* Make functions to retrieve this */
        PTRACE_CHECK(PTRACE_GETREGS, pid, NULL, &regs, NULL);

        s->args.sp = regs.TRACY_STACK_POINTER;

        if (s->child->denied_nr) {
            /* printf("DENIED SYSTEM CALL: Changing from %s to %s\n",
                    get_syscall_name(regs.TRACY_SYSCALL_REGISTER),
                    get_syscall_name(s->child->denied_nr));
            */
            s->syscall_num = s->child->denied_nr;
            s->args.syscall = s->child->denied_nr;
            s->child->denied_nr = 0;

            /* Args don't matter with denied syscalls */
            s->args.ip = regs.TRACY_IP_REG;
            s->type = TRACY_EVENT_SYSCALL;
            s->args.return_code = regs.TRACY_RETURN_CODE;
            s->args.sp = regs.TRACY_STACK_POINTER;

            check_syscall(s);
            return s;
        } else {
            s->args.syscall = regs.TRACY_SYSCALL_REGISTER;
            s->syscall_num = regs.TRACY_SYSCALL_REGISTER;

            if (t->opt & TRACY_VERBOSE)
                printf(_y("%04d System call: %s (%ld) Pre: %d")"\n",
                        s->child->pid, get_syscall_name(s->syscall_num),
                        s->syscall_num, !s->child->pre_syscall);
        }

        s->args.a0 = regs.TRACY_ARG_0;
        s->args.a1 = regs.TRACY_ARG_1;
        s->args.a2 = regs.TRACY_ARG_2;
        s->args.a3 = regs.TRACY_ARG_3;
        s->args.a4 = regs.TRACY_ARG_4;
        s->args.a5 = regs.TRACY_ARG_5;
        s->args.sp = regs.TRACY_STACK_POINTER;

        s->args.return_code = regs.TRACY_RETURN_CODE;
        s->args.ip = regs.TRACY_IP_REG;

        s->type = TRACY_EVENT_SYSCALL;

        check_syscall(s);

    } else if (signal_id == SIGTRAP) {

        if (t->opt & TRACY_VERBOSE) {
            /* XXX We probably want to move most of this logic out of the
             * verbose statement soon */
            PTRACE_CHECK(PTRACE_GETEVENTMSG, pid, NULL, &info, NULL);
            PTRACE_CHECK(PTRACE_GETSIGINFO, pid, NULL, &siginfo, NULL);

            puts(_y("Recursing due to SIGTRAP"));
            printf("SIGTRAP Info: %d, Status: %d, Signal id: %d\n", info,
                savedstatus, signal_id);
            printf("status>>8: %d\n", savedstatus>>8);

            printf("CLONE: %d\n", SIGTRAP | (PTRACE_EVENT_CLONE<<8));
            printf("VFORK: %d\n", SIGTRAP | (PTRACE_EVENT_VFORK<<8));
            printf("FORK: %d\n", SIGTRAP | (PTRACE_EVENT_FORK<<8));
            printf("EXEC: %d\n", SIGTRAP | (PTRACE_EVENT_EXEC<<8));
            printf("VFORK: %d\n", SIGTRAP | (PTRACE_EVENT_VFORK_DONE<<8));
            printf("TRACEEXIT: %d\n", SIGTRAP | (PTRACE_EVENT_EXIT<<8));

            printf("Signal info: %d\n", siginfo.si_code);
            if (siginfo.si_code == SI_KERNEL) {
                printf("SIGTRAP from kernel\n");
            }
            if (siginfo.si_code <= 0) {
                printf("SIGTRAP from userspace\n");
            }
        }

        /* Resume, set signal to 0; we don't want to pass SIGTRAP. */
        tracy_continue(s, 1);

        /* TODO: Replace this with goto or loop */
        return tracy_wait_event(t, c_pid);

    } else {
        if (t->opt & TRACY_VERBOSE)
            puts(_y("Signal for the child"));
        /* Signal for the child, pass it along. */
        s->signal_num = signal_id;
        s->type = TRACY_EVENT_SIGNAL;
    }

    return s;
}

/*
 * This function continues the execution of a process with pid s->pid.
 */
int tracy_continue(struct tracy_event *s, int sigoverride) {
    int sig = 0;

    /*  If data is nonzero and not SIGSTOP, it is interpreted as signal to be
     *  delivered to the child; otherwise, no signal is delivered. */
    if (s->type == TRACY_EVENT_SIGNAL) {
        sig = s->signal_num;

        s->signal_num = 0; /* Clear signal */
        if (s->child->tracy->opt & TRACY_VERBOSE)
            printf(_y("Passing along signal %s (%d) to child %d")"\n",
                get_signal_name(sig), sig, s->child->pid);
    }

    if (sigoverride)
        sig = 0;

    PTRACE_CHECK(PTRACE_SYSCALL, s->child->pid, NULL, sig, -1);

    return 0;
}

int tracy_kill_child(struct tracy_child *c) {
    int garbage;

    printf("tracy_kill_child: %d\n", c->pid);
    /*
     * PTRACE_KILL is deprecated
     * if (ptrace(PTRACE_KILL, c->pid)) {
    */

    kill(c->pid, SIGKILL);

    if (c->pre_syscall) {
        puts("Kill in pre");
        tracy_deny_syscall(c);
        ptrace(PTRACE_SYSCALL, c->pid, NULL, NULL);
    }

    waitpid(c->pid, &garbage, 0);

    PTRACE_CHECK(PTRACE_SYSCALL, c->pid, NULL, SIGKILL, -1);

    if (tracy_remove_child(c)) {
        puts("Could not remove child");
    }

    return 0;
}

int tracy_remove_child(struct tracy_child *c) {
    int r;
    r = ll_del(c->tracy->childs, c->pid);

    if (!r)
        free(c);

    return r;
}

int tracy_children_count(struct tracy* t) {
    struct soxy_ll_item * cur;
    int i = 0;
    cur = t->childs->head;

    while (cur) {
        cur = cur->next;
        i++;
    }

    return i;
}

/* Used to keep track of what is PRE and what is POST. */
int check_syscall(struct tracy_event *s) {
    s->child->pre_syscall = s->child->pre_syscall ? 0 : 1;
    return 0;
}

static const struct _syscall_to_str {
    char *name;
    int call_nr;
} syscall_to_string[] = {
#define DEF_SYSCALL(NAME) \
    {#NAME, SYS_ ## NAME},
    #include "def_syscalls.h"
    {NULL, -1}
};

/* Convert syscall number to syscall name */
char* get_syscall_name(int syscall)
{
    int i = 0;

    while (syscall_to_string[i].name) {
        if (syscall_to_string[i].call_nr == syscall)
            return syscall_to_string[i].name;

        i++;
    }

    return NULL;
}

static const struct _signal_to_str {
    char *name;
    int sig_nr;
} signal_to_string[] = {
#define DEF_SIGNAL(NAME) \
    {#NAME, NAME},
    #include "def_signals.h"
    {NULL, -1}
};

/* Convert signal number to signal name */
char* get_signal_name(int signal)
{
    int i = 0;

    while (signal_to_string[i].name) {
        if (signal_to_string[i].sig_nr == signal)
            return signal_to_string[i].name;

        i++;
    }

    return NULL;
}

/* Python hashing algorithm for strings */
static int hash_syscall(char * syscall) {
    int l, v, i;

    l = strlen(syscall);
    if (l < 1)
        return -1;

    v = (int)syscall[0];

    for(i = 0; i < l; i++)
        v = (1000003 * v) ^ (int)syscall[i];

    v = v ^ l;
    return v;
}

/*
 *
 * Simple hooking into system calls. Calls are passed by name to keep them
 * platform indepentent.
 *
 * TODO:
 *  - We need to figure out what exact arguments to pass to the hooks
 *  - We need to define the return values of the hooks. It should be possible to
 *  block / deny system calls based on the result of the hook. (Right?)
 *
 */
int tracy_set_hook(struct tracy *t, char *syscall, tracy_hook_func func) {

    struct soxy_ll_item *item;
    int hash;
    union {
            void *pvoid;
            tracy_hook_func pfunc;
        } _hax;

    hash = hash_syscall(syscall);

    item = ll_find(t->hooks, hash);
    _hax.pfunc = func;

    if (!item) {
        if (ll_add(t->hooks, hash, _hax.pvoid)) {
            return -1;
            /* Whoops */
        }
    } else {
        return -1;
    }

    return 0;
}

int tracy_set_default_hook(struct tracy *t, tracy_hook_func f) {
    if (t->defhook)
        return -1;

    t->defhook = f;

    return 0;
}

/* Find and execute hook. */
int tracy_execute_hook(struct tracy *t, char *syscall, struct tracy_event *e) {
    struct soxy_ll_item *item;
    int hash;
    union {
            void *pvoid;
            tracy_hook_func pfunc;
        } _hax;

    hash = hash_syscall(syscall);

    item = ll_find(t->hooks, hash);

    if (item) {
        /* printf("Executing hook for: %s\n", syscall); */

        /* ANSI C has some disadvantages too ... */
        _hax.pvoid = item->data;
        return _hax.pfunc(e);
    }

    if (t->defhook)
        return t->defhook(e);

    return TRACY_HOOK_NOHOOK;
}

/* Read a single ``word'' from child e->pid */
int tracy_peek_word(struct tracy_child *child, long from, long *word) {
    errno = 0;

    *word = ptrace(PTRACE_PEEKDATA, child->pid, from, NULL);

    if (errno)
        return -1;

    return 0;
}

/* Read a byte chunk using ptrace's peek/poke API 
 * This function is a lot slower than tracy_read_mem which uses the proc
 * filesystem for accessing the child's memory space.
 *
 * If this function errors the 'dest' memory is left in an undefined state.
 *
 * XXX: We currently do not align at word boundaries, furthermore we only read
 * whole words, this might cause trouble on some architectures.
 *
 */
ssize_t tracy_peek_mem(struct tracy_child *c, tracy_parent_addr_t dest,
        tracy_child_addr_t src, ssize_t n) {

    long *l_dest = (long*)dest;

    /* The long source address */
    long from;

    /* Force cast from (void*) to (long) */
    union {
        void *p_addr;
        long l_addr;
    } _cast_addr;

    /* The only way to check for a ptrace peek error is errno, so reset it */
    errno = 0;

    /* Convert source address to a long to be used by ptrace */
    _cast_addr.p_addr = src;
    from = _cast_addr.l_addr;

    /* Peek memory loop */
    while (n > 0) {
        *l_dest = ptrace(PTRACE_PEEKDATA, c->pid, from, NULL);
        if (errno)
            return -1;

        /* Update the various pointers */
        l_dest++;
        from += sizeof(long);
        n -= sizeof(long);
    }

    return from - _cast_addr.l_addr;
}

/* Open child's memory space */
static int open_child_mem(struct tracy_child *c)
{
    char proc_mem_path[18];

    /* Setup memory access via /proc/<pid>/mem */
    sprintf(proc_mem_path, "/proc/%d/mem", c->pid);
    c->mem_fd = open(proc_mem_path, O_RDWR);

    /* If opening failed, we allow us to continue without
     * fast access. We can fall back to other methods instead.
     */
    if (c->mem_fd == -1) {
        perror("tracy: open_child_mem");
        fprintf(stderr, "tracy: Warning: failed to open child memory @ '%s'\n",
            proc_mem_path);
        return -1;
    }

    return 0;
}

/* Returns bytes read */
static ssize_t tracy_ppm_read_mem(struct tracy_child *c,
        tracy_parent_addr_t dest, tracy_child_addr_t src, size_t n) {
    /* Open memory if it's not open yet */
    if (c->mem_fd < 0) {
        if (open_child_mem(c) < 0)
            return -2;
    }

    /* Try seeking this memory postion */
    if (lseek(c->mem_fd, (off_t)src, SEEK_SET) == (off_t)-1)
        return -1;

    errno = 0;

    /* And read. */
    return read(c->mem_fd, dest, n);
}

/* XXX The memory access functions should not be used for reading more than 2GB
 * on 32-bit because they will cause the error handling code to trigger incorrectly
 * while executing successfully
 */
ssize_t tracy_read_mem(struct tracy_child *child,
        tracy_parent_addr_t dest, tracy_child_addr_t src, size_t n) {
    int r;

    if (child->mem_fallback)
        return tracy_peek_mem(child, dest, src, n);

    r = tracy_ppm_read_mem(child, dest, src, n);

    /* The fallback should only trigger upon failure of opening the
     * child's memory, tracy_ppm_read_mem returns -2 when this happens.
     */
    if (r == -2 && (child->tracy->opt & TRACY_MEMORY_FALLBACK)) {
        child->mem_fallback = 1;
        r = tracy_peek_mem(child, dest, src, n);
    }

    return r;
}

int tracy_poke_word(struct tracy_child *child, long to, long word) {
    if (ptrace(PTRACE_POKEDATA, child->pid, to, word)) {
        perror("tracy_poke_word: pokedata");
        return -1;
    }

    return 0;
}

/* Write a byte chunk using ptrace's peek/poke API 
 * This function is a lot slower than tracy_write_mem which uses the proc
 * filesystem for accessing the child's memory space.
 *
 * If this function errors the 'dest' child memory is left in an undefined state.
 *
 * XXX: We currently do not align at word boundaries, furthermore we only read
 * whole words, this might cause trouble on some architectures.
 *
 * XXX: We could possibly return the negative of words successfully written
 * on error. When we do, we need to be careful because the negative value
 * returned is used to signal some faults in the tracy_ppm* functions.
 */
ssize_t tracy_poke_mem(struct tracy_child *c, tracy_child_addr_t dest,
        tracy_parent_addr_t src, ssize_t n) {

    long *l_src = (long*)src;

    /* The long target address */
    long to;

    /* Force cast from (void*) to (long) */
    union {
        void *p_addr;
        long l_addr;
    } _cast_addr;

    /* Convert source address to a long to be used by ptrace */
    _cast_addr.p_addr = dest;
    to = _cast_addr.l_addr;

    /* Peek memory loop */
    while (n > 0) {
        if (ptrace(PTRACE_POKEDATA, c->pid, to, *l_src))
            return -1;

        /* Update the various pointers */
        l_src++;
        to += sizeof(long);
        n -= sizeof(long);
    }

    return to - _cast_addr.l_addr;
}


static ssize_t tracy_ppm_write_mem(struct tracy_child *c,
        tracy_child_addr_t dest, tracy_parent_addr_t src, size_t n) {
    /* Open memory if it's not open yet */
    if (c->mem_fd < 0) {
        if (open_child_mem(c) < 0)
            return -2;
    }

    /* Try seeking this memory postion */
    if (lseek(c->mem_fd, (off_t)dest, SEEK_SET) == (off_t)-1)
        return -1;

    errno = 0;

    /* And write. */
    return write(c->mem_fd, src, n);
}

ssize_t tracy_write_mem(struct tracy_child *child,
        tracy_parent_addr_t dest, tracy_child_addr_t src, size_t n) {
    int r;

    if (child->mem_fallback)
        return tracy_poke_mem(child, dest, src, n);

    r = tracy_ppm_write_mem(child, dest, src, n);

    /* The fallback should only trigger upon failure of opening the
     * child's memory, tracy_ppm_write_mem returns -2 when this happens.
     */
    if (r == -2 && (child->tracy->opt & TRACY_MEMORY_FALLBACK)) {
        child->mem_fallback = 1;
        r = tracy_poke_mem(child, dest, src, n);
    }

    return r;
}

/* Execute mmap in the child process */
int tracy_mmap(struct tracy_child *child, tracy_child_addr_t *ret,
        tracy_child_addr_t addr, size_t length, int prot, int flags, int fd,
        off_t pgoffset) {
    struct tracy_sc_args a;

    a.a0 = (long) addr;
    a.a1 = (long) length;
    a.a2 = (long) prot;
    a.a3 = (long) flags;
    a.a4 = (long) fd;
    a.a5 = (long) pgoffset;

    /* XXX: Currently we make no distinction between calling
     * mmap and mmap2 here, however we should add an expression
     * that normalises the offset parameter passed to both flavors of mmap.
     */
    if (tracy_inject_syscall(child, TRACY_NR_MMAP, &a, (long*)ret))
        return -1;

    return 0;
}

/* Execute munmap in the child process */
int tracy_munmap(struct tracy_child *child, long *ret,
       tracy_child_addr_t addr, size_t length) {
    struct tracy_sc_args a;

    a.a0 = (long) addr;
    a.a1 = (long) length;

    if (tracy_inject_syscall(child, __NR_munmap, &a, ret)) {
        return -1;
    }

    return 0;
}

/*
 * For internal use only.
 *
 * Use this function to print out all the relevant registers.
 *
 */
int tracy_debug_current(struct tracy_child *child) {
    struct TRACY_REGS_NAME a;

    PTRACE_CHECK(PTRACE_GETREGS, child->pid, 0, &a, -1);

    printf("DEBUG: 0: %ld 1: %ld 2: %ld 3: %ld 4: %ld 5: %ld"
            "r: %ld, R: %ld, IP: %ld SP: %ld\n",
            a.TRACY_ARG_0, a.TRACY_ARG_1,
            a.TRACY_ARG_2, a.TRACY_ARG_3,
            a.TRACY_ARG_4, a.TRACY_ARG_5,
            a.TRACY_SYSCALL_REGISTER, a.TRACY_RETURN_CODE,
            a.TRACY_IP_REG, a.TRACY_STACK_POINTER
            );

    tracy_backtrace();

    return 0;
}

void tracy_backtrace(void) {
    void *array [40];
    size_t size;

    size = backtrace(array, 40);
    backtrace_symbols_fd(array, 10, 2);

    return;
}

int tracy_inject_syscall(struct tracy_child *child, long syscall_number,
        struct tracy_sc_args *a, long *return_code) {
    int garbage;

    if (child->pre_syscall) {
        if (tracy_inject_syscall_pre_start(child, syscall_number, a, NULL))
            return -1;

        child->inj.injecting = 0;
        tracy_continue(&child->event, 1);

        waitpid(child->pid, &garbage, 0);

        return tracy_inject_syscall_pre_end(child, return_code);
    } else {
        if (tracy_inject_syscall_post_start(child, syscall_number, a, NULL))
            return -1;

        child->inj.injecting = 0;

        tracy_continue(&child->event, 1);

        waitpid(child->pid, &garbage, 0);

        return tracy_inject_syscall_post_end(child, return_code);
    }
}

int tracy_inject_syscall_pre_start(struct tracy_child *child, long syscall_number,
        struct tracy_sc_args *a, tracy_hook_func callback) {

    PTRACE_CHECK(PTRACE_GETREGS, child->pid, 0, &child->inj.reg, -1);

    child->inj.cb = callback;
    child->inj.injecting = 1;
    child->inj.pre = 1;
    child->inj.syscall_num = syscall_number;

    return tracy_modify_syscall(child, syscall_number, a);
}


int tracy_inject_syscall_pre_end(struct tracy_child *child, long *return_code) {
    int garbage;
    struct TRACY_REGS_NAME newargs;

    PTRACE_CHECK(PTRACE_GETREGS, child->pid, 0, &newargs, -1);

    /* printf("Return code of getpid(): %ld\n", newargs.TRACY_RETURN_CODE); */
    *return_code = newargs.TRACY_RETURN_CODE;

    /* POST */
    child->inj.reg.TRACY_IP_REG -= TRACY_SYSCALL_OPSIZE;

    /* vvvv This is probably not required vvvv */
    child->inj.reg.TRACY_SYSCALL_N = child->inj.reg.TRACY_SYSCALL_REGISTER;

    PTRACE_CHECK(PTRACE_SETREGS, child->pid, 0, &child->inj.reg, -1);

    PTRACE_CHECK(PTRACE_SYSCALL, child->pid, NULL, 0, -1);

    /* Wait for PRE, this shouldn't take long as we literally only wait for
     * the OS to notice that we set the PC back it should give us control back
     * on PRE-syscall. */
    waitpid(child->pid, &garbage, 0);

    return 0;
}

int tracy_inject_syscall_post_start(struct tracy_child *child, long syscall_number,
        struct tracy_sc_args *a, tracy_hook_func callback) {
    int garbage;
    struct TRACY_REGS_NAME newargs;

    PTRACE_CHECK(PTRACE_GETREGS, child->pid, 0, &child->inj.reg, -1);

    child->inj.cb = callback;
    child->inj.injecting = 1;
    child->inj.pre = 0;
    child->inj.syscall_num = syscall_number;

    PTRACE_CHECK(PTRACE_GETREGS, child->pid, 0, &newargs, -1);

    /* POST, go back to PRE */
    newargs.TRACY_IP_REG -= TRACY_SYSCALL_OPSIZE;

    PTRACE_CHECK(PTRACE_SETREGS, child->pid, 0, &newargs, -1);

    PTRACE_CHECK(PTRACE_SYSCALL, child->pid, NULL, 0, -1);

    /* Wait for PRE, this shouldn't take long as we literally only wait for
     * the OS to notice that we set the PC back; it should give us control back
     * on PRE-syscall*/
    waitpid(child->pid, &garbage, 0);

    return tracy_modify_syscall(child, syscall_number, a);
}

int tracy_inject_syscall_post_end(struct tracy_child *child, long *return_code) {
    struct TRACY_REGS_NAME newargs;

    PTRACE_CHECK(PTRACE_GETREGS, child->pid, 0, &newargs, -1);

    *return_code = newargs.TRACY_RETURN_CODE;

    PTRACE_CHECK(PTRACE_SETREGS, child->pid, 0, &child->inj.reg, -1);

    return 0;
}

int tracy_modify_syscall(struct tracy_child *child, long syscall_number,
        struct tracy_sc_args *a) {

    /* change_syscall */
    struct TRACY_REGS_NAME newargs;

    PTRACE_CHECK(PTRACE_GETREGS, child->pid, 0, &newargs, -1);

    newargs.TRACY_SYSCALL_REGISTER = syscall_number;
    newargs.TRACY_SYSCALL_N = syscall_number;

    #ifdef __arm__
    /* ARM requires us to call this function to set the system call */
    PTRACE_CHECK(PTRACE_SET_SYSCALL, child->pid, 0, (void*)syscall_number, -1);
    #endif

    if (a) {
        newargs.TRACY_ARG_0 = a->a0;
        newargs.TRACY_ARG_1 = a->a1;
        newargs.TRACY_ARG_2 = a->a2;
        newargs.TRACY_ARG_3 = a->a3;
        newargs.TRACY_ARG_4 = a->a4;
        newargs.TRACY_ARG_5 = a->a5;
        newargs.TRACY_RETURN_CODE = a->return_code;
    }

    PTRACE_CHECK(PTRACE_SETREGS, child->pid, 0, &newargs, -1);

    return 0;
}

int tracy_deny_syscall(struct tracy_child *child) {
    int r, nr;

    /* TODO: Set ``return code'' for denied system call. Write expects
     * the bytes written for example. This could be done in the POST
     * hook of the denied system call. (Should be done, imho) */

    if (!child->pre_syscall) {
        fprintf(stderr, "ERROR: Calling deny on a POST system call");
        tracy_backtrace();
        return -1;
    }
    nr = child->event.syscall_num;
    r = tracy_modify_syscall(child, __NR_getpid, NULL);
    if (!r)
        child->denied_nr = nr;
    return r;
}

/* Used by the interrupt system to cancel the main loop */
static int main_loop_go_on = 0;

/* Handle SIGINT in tracy_main and shutdown smoothly */
static void _main_interrupt_handler(int sig)
{
    fprintf(stderr, _y("\ntracy: Received %s, commencing soft shutdown and "
        "disengaging signal handler.")"\n",
        get_signal_name(sig));
    signal(sig, SIG_DFL);

    /* Cancel main loop */
    main_loop_go_on = 0;

    return;
}

/* Main function for simple tracy based applications */
int tracy_main(struct tracy *tracy) {
    struct tracy_event *e;
    int hook_ret;

    /* Setup interrupt handler */
    main_loop_go_on = 1;
    signal(SIGINT, _main_interrupt_handler);

    while (main_loop_go_on) {
        start:
        e = tracy_wait_event(tracy, -1);

        if (e->type == TRACY_EVENT_NONE) {
            break;
        } else if (e->type == TRACY_EVENT_INTERNAL) {
            /*
            printf("Internal event for syscall: %s\n",
                    get_syscall_name(e->syscall_num));
            */
        }
        if (e->type == TRACY_EVENT_SIGNAL) {
            printf(_y("Signal %s (%ld) for child %d")"\n",
                get_signal_name(e->signal_num), e->signal_num, e->child->pid);
        } else

        if (e->type == TRACY_EVENT_SYSCALL) {
            /* TODO: Duplicate code */
            if (e->child->pre_syscall) {
                if (get_syscall_name(e->syscall_num)) {
                    hook_ret = tracy_execute_hook(tracy,
                            get_syscall_name(e->syscall_num), e);
                    switch (hook_ret) {
                        case TRACY_HOOK_CONTINUE:
                            break;
                        case TRACY_HOOK_KILL_CHILD:
                            tracy_kill_child(e->child);
                            /* We don't want to call tracy_continue(e, 0); */
                            goto start;

                        case TRACY_HOOK_ABORT:
                            tracy_quit(tracy, 1);
                            break;
                        case TRACY_HOOK_NOHOOK:
                            break;
                    }
                }
            } else {
                if (get_syscall_name(e->syscall_num)) {
                    hook_ret = tracy_execute_hook(tracy,
                            get_syscall_name(e->syscall_num), e);
                    switch (hook_ret) {
                        case TRACY_HOOK_CONTINUE:
                            break;
                        case TRACY_HOOK_KILL_CHILD:
                            tracy_kill_child(e->child);
                            /* We don't want to call tracy_continue(e, 0); */
                            goto start;

                        case TRACY_HOOK_ABORT:
                            tracy_quit(tracy, 1);
                            break;
                        case TRACY_HOOK_NOHOOK:
                            break;
                    }
                }
            }
        } else

        if (e->type == TRACY_EVENT_QUIT) {
            if (tracy->opt & TRACY_VERBOSE)
                printf(_b("EVENT_QUIT from %d with signal %s (%ld)\n"),
                        e->child->pid, get_signal_name(e->signal_num),
                        e->signal_num);
            if (e->child->pid == tracy->fpid) {
                if (tracy->opt & TRACY_VERBOSE)
                    printf(_g("Our first child died.\n"));
            }

            tracy_remove_child(e->child);
            goto start;
        }

        if (!tracy_children_count(tracy)) {
            break;
        }

        tracy_continue(e, 0);
    }

    /* Tear down interrupt handler */
    signal(SIGINT, SIG_DFL);

    return 0;
}

/* This function is used as a callback by the safe-fork
 * functions.
 *
 * It's main purpose is to set the correct fork result
 * and restore PRE/POST order.
 */
static int restore_fork(struct tracy_event *e) {
    struct TRACY_REGS_NAME args;
    pid_t child_pid;

    child_pid = e->child->safe_fork_pid;
/*
    puts("RESTORE FORK");
*/

    if (e->child->pre_syscall)
        e->child->pre_syscall = 0;
    else
        e->child->pre_syscall = 1;


    printf("pid: %ld\n", e->args.return_code);

    PTRACE_CHECK(PTRACE_GETREGS, e->child->pid, 0, &args, -1);

    args.TRACY_RETURN_CODE = child_pid;
    PTRACE_CHECK(PTRACE_SETREGS, e->child->pid, 0, &args, -1);
/*
    printf("Set return code to %d\n", child_pid);
*/
    return 0;
}

/* Safe forking/cloning
 *
 * This function takes over the PRE fase of a child process' fork
 * syscall. It then forks the child in a controlled manor ensuring
 * tracy will be able to trace the forked process.
 * This function returns the pid of the new child in new_child upon success.
 *
 * Upon error the return value will be -1 and errno will be set appropriately.
 *
 * FIXME: This function memleaks a page upon failure in the child atm.
 * TODO: This function needs a lot more error handling than it contains now.
 */
int tracy_safe_fork(struct tracy_child *c, pid_t *new_child)
{
    tracy_child_addr_t mmap_ret;
    int status;
    long ip;
    struct TRACY_REGS_NAME args, args_ret;
    const long page_size = sysconf(_SC_PAGESIZE);
    pid_t child_pid;

/*
    puts("SAFE_FORKING!");
*/
    /* First let's allocate a page in the child which we shall use
     * to write a piece of forkcode (see trampy.c) to.
     */
   tracy_mmap(c, &mmap_ret,
            NULL, page_size,
            PROT_READ | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS,
            -1, 0
            );

    /* I know this is FUBAR, but bear with me 
     *
     * Check for an error value in the return code/address.
     */
    if (mmap_ret < ((tracy_child_addr_t)NULL) &&
            mmap_ret > ((tracy_child_addr_t)-4096)) {
        errno = -(long)mmap_ret;
        perror("tracy_mmap");
        return -1;
    }
/*
    printf("mmap addr: %p\n", (void*)mmap_ret);
*/

    /* XXX - Debug
    printf("trampy_get_safe_entry() = %p\ntrampy_get_code_size() = %d\n",
        trampy_get_safe_entry(), trampy_get_code_size());
    */

    /* Write the piece of code to the child process */
    if (tracy_write_mem(c, (void*) mmap_ret,
            trampy_get_safe_entry(),
            trampy_get_code_size()) < 0) {
        perror("tracy_write_mem");
        return -1;
    }

    /* Fetch the registers to store the original forking syscall and more importantly
     * the instruction pointer.
     */
    PTRACE_CHECK(PTRACE_GETREGS, c->pid, 0, &args, -1);

    /* Deny so we can set the IP on the denied post and do our own fork in a
     * controlled environment */
    tracy_deny_syscall(c);
    c->denied_nr = 0;
    PTRACE_CHECK(PTRACE_SYSCALL, c->pid, 0, 0, -1);
/*
    puts("DENIED, in PRE");
*/
    waitpid(c->pid, &status, 0);
/*
    puts("AFTER DENIED, entered POST");
*/

    /* Okay, the child is now in POST syscall mode, and it has
     * just executed a bogus syscall (getpid) inserted by deny syscall.
     *
     * Setup a fork syscall and point the processor to the injected code.
     */
    args.TRACY_SYSCALL_REGISTER = __NR_fork;
    args.TRACY_SYSCALL_N = __NR_fork;

    ip = args.TRACY_IP_REG;
    args.TRACY_IP_REG = (long)mmap_ret;

    PTRACE_CHECK(PTRACE_SETREGS, c->pid, 0, &args, -1);

/*
    printf("The IP was changed from %p to %p\n", (void*)ip, (void*)mmap_ret);

    puts("POST, Entering PRE");
*/

    PTRACE_CHECK(PTRACE_SYSCALL, c->pid, 0, 0, -1);
    waitpid(c->pid, &status, 0);

    /* At this moment the child is in PRE mode in the trampy code,
     * trying to execute a sched_yield, which we shall now make
     * into a fork syscall.
     */
    PTRACE_CHECK(PTRACE_GETREGS, c->pid, 0, &args_ret, -1);
/*
    printf("The IP is now %p\n", (void*)args_ret.TRACY_IP_REG);
    printf("Modifying syscall back to fork\n");
*/

    /* TODO: Replace the following with a single call to
     * tracy_modify_syscall().
     */
    args_ret.TRACY_SYSCALL_REGISTER = __NR_fork;
    args_ret.TRACY_SYSCALL_N = __NR_fork;

    /* On ARM the syscall number is not included in any register, so we have
     * this special ptrace option to modify the syscall
     */
    #ifdef __arm__
    PTRACE_CHECK(PTRACE_SET_SYSCALL, c->pid, 0, (void*)__NR_fork, -1);
    #endif

    PTRACE_CHECK(PTRACE_SETREGS, c->pid, 0, &args_ret, -1);

/*
    puts("PRE, Entering POST");
*/

    /* Now execute the actual fork.
     *
     * Afterwards the parent will immediately come to a halt
     * while the child will wait for us to attach. See 'trampy.c'
     * for more details.
     */
    PTRACE_CHECK(PTRACE_SYSCALL, c->pid, 0, 0, -1);
    waitpid(c->pid, &status, 0);

    PTRACE_CHECK(PTRACE_GETREGS, c->pid, 0, &args_ret, -1);

/*
    printf("The IP is now %p\n", (void*)args_ret.TRACY_IP_REG);
    puts("POST");
*/

    PTRACE_CHECK(PTRACE_GETREGS, c->pid, 0, &args_ret, -1);

    /* FIXME: We don't check if the fork failed
     * which we really should since there is no point in
     * attaching to a failed fork.
     */
    child_pid = args_ret.TRACY_RETURN_CODE;

    /* Return PID to caller if they're interested. */
    if (new_child)
        *new_child = child_pid;

    c->safe_fork_pid = child_pid;
    printf("Fork return value: %d\n", child_pid);

    /* Now point the parent process after the original fork
     * syscall instruction.
     */
    args_ret.TRACY_IP_REG = ip;

    PTRACE_CHECK(PTRACE_SETREGS, c->pid, 0, &args_ret, -1);

    tracy_inject_syscall_post_start(c, __NR_getpid, NULL, restore_fork);

    /* Attach to the new child */
    printf("Attaching to %d...\n", child_pid);
    PTRACE_CHECK(PTRACE_ATTACH, child_pid, 0, 0, -1);
    waitpid(child_pid, &status, 0);

/*
    if (ptrace(PTRACE_SETREGS, child_pid, 0, &args))
        perror("SETREGS");
*/

    /* Restore the new child as well*/
    args.TRACY_IP_REG = ip;
    args.TRACY_RETURN_CODE = 0;

    PTRACE_CHECK(PTRACE_SETREGS, child_pid, 0, &args, -1);

    PTRACE_CHECK(PTRACE_SETOPTIONS, child_pid, 0, PTRACE_O_TRACESYSGOOD, -1);

    /* Continue the new child */
    PTRACE_CHECK(PTRACE_SYSCALL, child_pid, 0, 0, -1);

    /* TODO: We should now munmap the pages in both the parent and the child.
     * Unless ofc. we created a thread which shares VM in which case we should
     * munmap only once.
     */

    return 0;
}

