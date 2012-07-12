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
 * tracy-event.c: ptrace event handling routines.
 *
 * Waiting for an event, handling internal events and
 * continueing the child.
 */
#include <stdio.h>
#include <errno.h>

#include <sys/syscall.h>
#include <sys/ptrace.h>

#include "tracy.h"

/* Used to keep track of what is PRE and what is POST. */
static int check_syscall(struct tracy_event *s) {
    s->child->pre_syscall = s->child->pre_syscall ? 0 : 1;
    return 0;
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

static int tracy_handle_signal_hook(struct tracy_event *e, int *suppress) {
    int hook_ret;

    struct tracy *tracy;
    tracy = e->child->tracy;

    hook_ret = tracy->signal_hook ? tracy->signal_hook(e) : TRACY_HOOK_NOHOOK;
    switch (hook_ret) {
        case TRACY_HOOK_CONTINUE:
            break;

        case TRACY_HOOK_SUPPRESS:
            printf("Setting child suppress\n");
            *suppress = 1;
            break;

        case TRACY_HOOK_KILL_CHILD:
            tracy_kill_child(e->child);
            return 1;

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

    return 0;
}

static int tracy_handle_syscall_hook(struct tracy_event *e) {
    int hook_ret;

    struct tracy *tracy;
    char *name;

    tracy = e->child->tracy;

    name = get_syscall_name(e->syscall_num);

    if (!name) {
        printf("Could not get syscall name: %ld\n", e->syscall_num);
        tracy_backtrace();
        tracy_quit(e->child->tracy, 1);
    }
    hook_ret = tracy_execute_hook(tracy, name, e);
    switch (hook_ret) {
        case TRACY_HOOK_CONTINUE:
            break;

        case TRACY_HOOK_KILL_CHILD:
            tracy_kill_child(e->child);
            return 1;

        case TRACY_HOOK_DENY:
            if(e->child->pre_syscall) {
                tracy_deny_syscall(e->child);
            } else {
                fprintf(stderr, "Deny in post. Stopping.\n");
                tracy_quit(tracy, 1);
            }

            break;

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

    return 0;
}

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

    start:
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
            goto start;
            /*return tracy_wait_event(t, c_pid);*/
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

            /* Set the system call numbers back to what they were before the
             * deny to ensure proper hooks are called. */
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

            if (tracy_handle_syscall_hook(s)) {
                /* TODO: Child got killed. Event type -> quit */
                s->type = TRACY_EVENT_QUIT;
                s->signal_num = SIGKILL;
            }

            return s;
        }

        s->args.syscall = regs.TRACY_SYSCALL_REGISTER;
        s->syscall_num = regs.TRACY_SYSCALL_REGISTER;

        /*
        if (TRACY_PRINT_SYSCALLS(t))
            printf(_y("%04d System call: %s (%ld) Pre: %d")"\n",
                    s->child->pid, get_syscall_name(s->syscall_num),
                    s->syscall_num, !s->child->pre_syscall);
            */

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

        if (tracy_handle_syscall_hook(s)) {
            /* TODO: Child got killed. Event type -> quit */
            s->type = TRACY_EVENT_QUIT;
            s->signal_num = SIGKILL;

            return s;
        }

        if (s->child->denied_nr) {
            if (!tracy_internal_syscall(s)) {
                /* TODO: We currently don't generate POST events if
                 * tracy_internal_syscall returns 0. This due to the fact
                 * that tracy_internal_syscall already resumes the
                 * target process. */
                goto start;
            }
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

        goto start;
        /*return tracy_wait_event(t, c_pid);*/

    } else if (signal_id == SIGSTOP && !s->child->received_first_sigstop) {
        if (TRACY_PRINT_SIGNALS(t))
            fprintf(stderr, "SIGSTOP ignored: pid = %d\n", pid);

        s->child->received_first_sigstop = 1;
        tracy_continue(s, 1);
        goto start;
    } else {
        if (TRACY_PRINT_SIGNALS(t))
            fprintf(stderr, _y("Signal for child: %d")"\n", pid);

        /* Signal for the child, pass it along. */
        s->signal_num = signal_id;
        s->type = TRACY_EVENT_SIGNAL;

        /* Signal hook here */
        if (tracy_handle_signal_hook(s, &(s->child->suppress))) {
            goto start;
        }
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
            fprintf(stderr, _y("Passing along signal %s (%d) to child %d")"\n",
                get_signal_name(sig), sig, s->child->pid);
    }

    if (s->child->suppress) {
        fprintf(stderr, "Surpressing signal: %s\n", get_signal_name(sig));
        sig = 0;
        s->child->suppress = 0;
    }

    if (sigoverride)
        sig = 0;

    PTRACE_CHECK(PTRACE_SYSCALL, s->child->pid, NULL, sig, -1);

    return 0;
}

