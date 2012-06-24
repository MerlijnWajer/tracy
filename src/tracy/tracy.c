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
#include <sys/types.h>

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
#include <sys/ptrace.h>
#include <sched.h>

#include <sys/mman.h>

#include "ll.h"
#include "tracy.h"

#include <execinfo.h>

/* Foreground PID, used by tracy main's interrupt handler */
static pid_t global_fpid;

/* Static functions */
static int check_syscall(struct tracy_event *s);

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
        /* TODO: Does this even work */
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
            PTRACE_CHECK_NORETURN(PTRACE_DETACH, tc->pid, NULL, NULL);
            /* TODO: What can we do in case of failure? */
        } else {
            fprintf(stderr, _b("Killing child %d")"\n", tc->pid);
            tracy_kill_child(tc);
        }

        /* Free data and fetch next item */
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
    tc->frozen_by_vfork = 0;
    tc->received_first_sigstop = 0;
    tc->denied_nr = 0;
    tc->tracy = t;
    tc->custom = NULL;

    tc->event.child = tc;

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
            fprintf(stderr, "PTRACE_TRACEME failed.\n");
            _exit(1);
        }

        /* Give the parent to chance to set some extra tracing options before we
         * restart the child and let it call exec() */
        raise(SIGTRAP);

        if (argc == 1) {
            execv(argv[0], argv);
        } else {
            execv(argv[0], argv);
        }

        if (errno) {
            perror("fork_trace_exec");
            fprintf(stderr, "execv failed.\n");
            _exit(1);
        }
    }

    if (pid == -1)
        return NULL;

    /* Parent */
    if (t->fpid == 0) {
        t->fpid = pid;

        /* Also set global FPID used by tracy_main's interrupt handler */
        global_fpid = pid;
    }

    /* Wait for SIGTRAP from the child */
    waitpid(pid, &status, __WALL);

    signal_id = WSTOPSIG(status);
    if (signal_id != SIGTRAP) {
        fprintf(stderr, "fork_trace_exec: child signal was not SIGTRAP.\n");
        kill(pid, SIGKILL);
        waitpid(pid, &status, 0);
        return NULL;
    }

    r = ptrace(PTRACE_SETOPTIONS, pid, NULL, (void*)ptrace_options);
    if (r) {
        fprintf(stderr, "fork_trace_exec: ptrace(PTRACE_SETOPTIONS) failed.\n");
        kill(pid, SIGKILL);
        waitpid(pid, &status, 0);
        return NULL;
    }

    /* We have made sure we will trace each system call of the child, including
     * the system calls of the children of the child, so the child can now
     * resume. */
    r = ptrace(PTRACE_SYSCALL, pid, NULL, 0);
    if (r) {
        fprintf(stderr, "fork_trace_exec: ptrace(PTRACE_SYSCALL) failed.\n");
        kill(pid, SIGKILL);
        waitpid(pid, &status, 0);
        return NULL;
    }

    tc = malloc_tracy_child(t, pid);
    if (!tc) {
        fprintf(stderr, "fork_trace_exec: malloc_tracy_child failed.\n");
        kill(pid, SIGKILL);
        waitpid(pid, &status, 0);
        return NULL;
    }

    /* This child has been created by us - I doesn't get a SIGSTOP that we want
     * to ignore. */
    tc->received_first_sigstop = 1;

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
    waitpid(pid, &status, __WALL);

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
    tc->received_first_sigstop = 1;

    ll_add(t->childs, tc->pid, tc);

    /* TODO: Special event for attached child? */
    if (t->se.child_create)
        (t->se.child_create)(tc);
    return tc;
}

struct tracy_child * tracy_add_child(struct tracy *t, int pid) {
    struct tracy_child * child;

    child = malloc_tracy_child(t, pid);
    if (!child) {
        perror("Cannot allocate structure for new child");
        return NULL; /* TODO Kill the child ? */
    }

    ll_add(t->childs, pid, child);

    if (t->se.child_create)
        (t->se.child_create)(child);

    return child;
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

/* HELP */
static int tracy_internal_syscall(struct tracy_event *s) {
    pid_t child;
    struct tracy_child *new_child;

    if (!(s->child->tracy->opt & TRACY_USE_SAFE_TRACE))
        return -1;

    if (s->child->frozen_by_vfork) {
        printf(_r("Resuming a parent-role child in a vfork operation")"\n");
        s->child->frozen_by_vfork = 0;

        /* Restore post-vfork values */
        s->args.TRAMPY_PID_ARG = s->child->orig_trampy_pid_reg;
        s->args.return_code = s->child->orig_return_code;
        s->args.ip = s->child->orig_pc;

        /* Finally update child registers */
        /* TODO: Check return value? */
        tracy_modify_syscall(s->child, s->args.syscall, &s->args);
    }

    if (!s->child->pre_syscall)
        return -1;


    switch(s->syscall_num) {
        case SYS_fork:
            printf("Internal Syscall %s\n", get_syscall_name(s->syscall_num));
            if (tracy_safe_fork(s->child, &child)) {
                printf("tracy_safe_fork failed!\n");
                tracy_debug_current(s->child);
                /* Probably kill child, or at least make sure it can't fork */
                return -1;
            }
            printf("New child: %d\n", child);

            new_child = tracy_add_child(s->child->tracy, child);

            printf("Added and resuming child\n");
            tracy_continue(&new_child->event, 1);

            printf("Continue parent\n");
            tracy_continue(s, 1);

            printf("Done!\n");
            return 0;
            break;

        case SYS_clone:
            printf("Internal Syscall %s\n", get_syscall_name(s->syscall_num));
            if (tracy_safe_fork(s->child, &child)) {
                printf("tracy_safe_fork failed!\n");
                tracy_debug_current(s->child);
                /* XXX REMOVE ME*/
                /*abort();*/
                /* Probably kill child, or at least make sure it can't fork */
                return -1;
            }
            printf("New child: %d\n", child);

            new_child = tracy_add_child(s->child->tracy, child);

            tracy_debug_current(new_child);

            printf("Added and resuming child\n");
            tracy_continue(&new_child->event, 1);

            if (!s->child->frozen_by_vfork) {
                printf("Continue parent\n");
                tracy_continue(s, 1);
            } else {
                printf("Not continuing parent\n");
            }

            printf("Done!\n");
            return 0;
            break;

        case SYS_vfork:
            printf("Internal Syscall %s\n", get_syscall_name(s->syscall_num));
            if (tracy_safe_fork(s->child, &child)) {
                printf("tracy_safe_fork failed!\n");
                tracy_debug_current(s->child);
                /* Probably kill child, or at least make sure it can't fork */
                return -1;
            }
            printf("New child: %d\n", child);

            new_child = tracy_add_child(s->child->tracy, child);

            printf("Added and resuming child\n");
            tracy_continue(&new_child->event, 1);

            /*
            printf("Continue parent\n");
            tracy_continue(s, 1);
            */

            printf("Done!\n");
            return 0;
            break;

        default:
            break;
    }

    return -1;
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

            tc = tracy_add_child(t, pid);
            if (!tc) {
                return NULL;
            }

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

            /* Args don't matter with denied syscalls */
            s->args.ip = regs.TRACY_IP_REG;
            s->type = TRACY_EVENT_SYSCALL;

            /* Set return code to -EPERM to indicate a denied system call. */
            s->args.return_code = -EPERM;
            s->args.sp = regs.TRACY_STACK_POINTER;

            /* TODO: Check return value? */
            tracy_modify_syscall(s->child, s->child->denied_nr, &(s->args));
            s->child->denied_nr = 0;

            check_syscall(s);
            return s;
        } else {
            s->args.syscall = regs.TRACY_SYSCALL_REGISTER;
            s->syscall_num = regs.TRACY_SYSCALL_REGISTER;

            if (TRACY_PRINT_SYSCALLS(t))
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

        /* If we fork, then I can't think of a way to nicely send a pre and post
         * fork event to the user. XXX TODO FIXME */
        check_syscall(s);

        if (!tracy_internal_syscall(s)) {
            return tracy_wait_event(t, c_pid);
        }

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

        /* Resume, set signal to 0; we don't want to pass SIGTRAP.
         * TODO: Unless it is sent by userspace? */
        tracy_continue(s, 1);

        /* TODO: Replace this with goto or loop */
        return tracy_wait_event(t, c_pid);

    } else if (signal_id == SIGSTOP && !s->child->received_first_sigstop) {
        if (TRACY_PRINT_SIGNALS(t))
            printf("SIGSTOP ignored: pid = %d\n", pid);

        s->child->received_first_sigstop = 1;
        tracy_continue(s, 1);
        return tracy_wait_event(t, c_pid);
    } else {
        if (TRACY_PRINT_SIGNALS(t))
            printf(_y("Signal for child: %d")"\n", pid);
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
        if (TRACY_PRINT_SIGNALS(s->child->tracy))
            printf(_y("Passing along signal %s (%d) to child %d")"\n",
                get_signal_name(sig), sig, s->child->pid);
    }

    if (sigoverride)
        sig = 0;

    PTRACE_CHECK(PTRACE_SYSCALL, s->child->pid, NULL, sig, -1);

    return 0;
}

int tracy_kill_child(struct tracy_child *c) {
    if (c->tracy->opt & TRACY_VERBOSE)
        printf("tracy_kill_child: %d\n", c->pid);

    kill(c->pid, SIGKILL);

    waitpid(c->pid, NULL, __WALL);

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
static int check_syscall(struct tracy_event *s) {
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
 * platform independent.
 *
 *
 * XXX: This is not true^, we can just use SYS_foo too. (Although SYS_clone does
 * not exist on say, BSD)
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

/*
 * For internal use only.
 *
 * Use this function to print out all the relevant registers.
 *
 */
int tracy_debug_current(struct tracy_child *child) {
    return tracy_debug_current_pid(child->pid);
}

int tracy_debug_current_pid(pid_t pid) {
    struct TRACY_REGS_NAME a;

    PTRACE_CHECK(PTRACE_GETREGS, pid, 0, &a, -1);

    printf("DEBUG: 0: %ld 1: %ld 2: %ld 3: %ld 4: %ld 5: %ld"
            " s: %ld, R: %ld, PC: %ld SP: %ld\n",
            a.TRACY_ARG_0, a.TRACY_ARG_1,
            a.TRACY_ARG_2, a.TRACY_ARG_3,
            a.TRACY_ARG_4, a.TRACY_ARG_5,
            a.TRACY_SYSCALL_REGISTER, a.TRACY_RETURN_CODE,
            a.TRACY_IP_REG, a.TRACY_STACK_POINTER
            );

    printf("DEBUG: 0: %lx 1: %lx 2: %lx 3: %lx 4: %lx 5: %lx"
            " s: %lx, R: %lx, PC: %lx SP: %lx\n",
            a.TRACY_ARG_0, a.TRACY_ARG_1,
            a.TRACY_ARG_2, a.TRACY_ARG_3,
            a.TRACY_ARG_4, a.TRACY_ARG_5,
            a.TRACY_SYSCALL_REGISTER, a.TRACY_RETURN_CODE,
            a.TRACY_IP_REG, a.TRACY_STACK_POINTER
            );

    /*tracy_backtrace();*/

    return 0;
}

void tracy_backtrace(void) {
    void *array [40];
    size_t size;

    size = backtrace(array, 40);
    if (!size) {
        fprintf(stderr, "Backtrace failed!\n");
        return;
    }
    backtrace_symbols_fd(array, 10, 2);

    return;
}

/* Used by the interrupt system to cancel the main loop */
static int main_loop_go_on = 0;

/* Handle SIGINT in tracy_main and shutdown smoothly */
static void _main_interrupt_handler(int sig)
{
    if (kill(global_fpid, SIGINT) < 0) {
        if (errno == ESRCH)
            fprintf(stderr, _y("\ntracy: Received %s, foreground PID "
                "does not exists, killing all."), get_signal_name(sig));
        else
            fprintf(stderr, _y("\ntracy: Received %s, kill(%i, SIGINT) failed: %s"),
                get_signal_name(sig), global_fpid, strerror(errno));

        /* Reset to default so tracy can be killed */
        signal(sig, SIG_DFL);

        /* Cancel main loop */
        main_loop_go_on = 0;
    }

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
        if (!e) {
            fprintf(stderr, "tracy_main: tracy_wait_Event returned NULL\n");
            continue;
        }

        if (e->type == TRACY_EVENT_NONE) {
            break;
        } else if (e->type == TRACY_EVENT_INTERNAL) {
            /*
            printf("Internal event for syscall: %s\n",
                    get_syscall_name(e->syscall_num));
            */
        }
        if (e->type == TRACY_EVENT_SIGNAL) {
            if (TRACY_PRINT_SIGNALS(tracy)) {
                printf(_y("Signal %s (%ld) for child %d")"\n",
                    get_signal_name(e->signal_num), e->signal_num, e->child->pid);
            }
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
                        default:
                            fprintf(stderr, "Invalid hook return: %d. Stopping.\n", hook_ret);
                            tracy_quit(tracy, 1);
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
                        default:
                            fprintf(stderr, "Invalid hook return: %d. Stopping.\n", hook_ret);
                            tracy_quit(tracy, 1);
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

