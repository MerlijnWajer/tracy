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

#include <string.h>

#include "tracy.h"

/* Used to keep track of the system call state of a child.
 * That is, whether the child is in PRE or POST system call state. */
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
        tracy_modify_syscall_regs(s->child, s->args.syscall, &s->args);
        tracy_modify_syscall_args(s->child, s->args.syscall, &s->args);
    }

    if (!s->child->pre_syscall)
        return -1;


    switch(s->syscall_num) {
#pragma message "SYS_{fork,vfork,clone} cannot be used directly; not abi safe"
        /* TODO, FIXME XXX: SYS_fork is not always valid, depends on the ABI */
        case SYS_fork:
            printf("Internal Syscall %s\n", get_syscall_name_abi(s->syscall_num, s->abi));
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

#if 0
            printf("Continue parent\n");
            tracy_continue(s, 1);
#endif

            printf("Done!\n");
            return 0;
            break;

        case SYS_clone:
            printf("Internal Syscall %s\n", get_syscall_name_abi(s->syscall_num, s->abi));
            if (tracy_safe_fork(s->child, &child)) {
                printf("tracy_safe_fork failed!\n");
                tracy_debug_current(s->child);
#pragma message "We still need to decide if we want to kill a child or not, perhaps"\
                " a strict flag?"
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
#if 0
                printf("Continue parent\n");
#endif
                tracy_continue(s, 1);
            } else {
                printf("Not continuing parent\n");
            }

            printf("Done!\n");
            return 0;
            break;

        case SYS_vfork:
            printf("Internal Syscall %s\n", get_syscall_name_abi(s->syscall_num, s->abi));
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

/* Empty tracy event.
 * This is returned by tracy_wait_event when all the children have died. */
#pragma message "none_event needs to be nulled"
static struct tracy_event none_event; /* TODO XXX FIXME NULL THIS */

/* Function to handle the signal hook.
 * If TRACY_HOOK_SUPPRESS is set, suppress is set to 1 and the next
 * tracy_continue will suppress the signal.
 */
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

        case TRACY_HOOK_DETACH_CHILD:
            tracy_detach_child(e->child);
            return 1; /* TODO: Why 1? */

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

/*
 * Function to handle per-system call hooks.
 * Action taken depends on whether a hook exists at all.
 * If the hook exists, action taken depends on the hook return value.
 */
static int tracy_handle_syscall_hook(struct tracy_event *e) {
    int hook_ret;

    struct tracy *tracy;
    char *name;

    tracy = e->child->tracy;

    name = get_syscall_name_abi(e->syscall_num, e->abi);

    if (!name) {
        return 0;
    }
    hook_ret = tracy_execute_hook(tracy, name, e);
    switch (hook_ret) {
        case TRACY_HOOK_CONTINUE:
            break;

        case TRACY_HOOK_DETACH_CHILD:
            tracy_detach_child(e->child);
            return 1; /* TODO: Why 1? */

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
    int status, signal_id, info;
    siginfo_t siginfo;
    pid_t pid;
    struct TRACY_REGS_NAME regs;
    struct tracy_child *tc;
    struct tracy_event *s;
    struct tracy_ll_item *item;

    start:
    s = NULL;

    /* Wait for changes */
    pid = waitpid(c_pid, &status, __WALL);

    /* Something went wrong. */
    if (pid == -1) {
        if (errno == EINTR) {
            return NULL;
        }

        /* If we were not interrupted, we no longer have any children. */
        return &none_event;
    }

    /* Does the child exist? */
    item = ll_find(t->childs, pid);

    /* If not, add it to our list. */
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
        /* If the child exists, use its event structure */
        s = &(((struct tracy_child*)(item->data))->event);
        s->child = item->data;
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

    /* TODO: 0 is an invalid type */
    s->type = 0;
    s->syscall_num = 0;
    s->signal_num = 0;

    /* Extract signal */
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

    /* PTRACE_O_TRACESYSGOOD makes it easier to distinguish
     * normal SIGTRAP signals from ptrace SIGTRAL signals.
     *
     * TODO: Other OS'es don't have this
     */
    if (signal_id == (SIGTRAP | 0x80)) {
        /* Make functions to retrieve this */
        PTRACE_CHECK(PTRACE_GETREGS, pid, NULL, &regs, NULL);

        s->args.sp = regs.TRACY_STACK_POINTER;

        /* If we previously denied a system call, now is the time to set
         * the return code and restore the registers. */
        if (s->child->denied_nr) {
            /* printf("DENIED SYSTEM CALL: Changing from %s to %s\n",
                    get_syscall_name(regs.TRACY_SYSCALL_REGISTER),
                    get_syscall_name(s->child->denied_nr));
            */

            /* Set the system call numbers back to what they were before the
             * deny to ensure proper hooks are called. */
            s->syscall_num = s->child->denied_nr;
            s->args.syscall = s->child->denied_nr;

            /* Args don't matter with denied syscalls, so we don't set them */
            s->args.ip = regs.TRACY_IP_REG;
            s->type = TRACY_EVENT_SYSCALL;

            /* Set return code to -EPERM to indicate a denied system call. */
            s->args.return_code = -EPERM;
            s->args.sp = regs.TRACY_STACK_POINTER;

            if (tracy_modify_syscall_regs(s->child, s->child->denied_nr, &(s->args))) {
                fprintf(stderr, "tracy_modify_syscall_regs failed\n");
                tracy_backtrace();
                /* TODO: Kill child? */
#pragma message "Kill child here?"
            }
            if (tracy_modify_syscall_args(s->child, s->child->denied_nr, &(s->args))) {
                fprintf(stderr, "tracy_modify_syscall_args failed\n");
                tracy_backtrace();
                /* TODO: Kill child? */
#pragma message "Kill child?"
            }
            s->child->denied_nr = 0;

            check_syscall(s);

            if (tracy_handle_syscall_hook(s)) {
                /* Child got killed. Event type -> quit */
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

        /* Detect ABI here */
        s->args.ip = regs.TRACY_IP_REG;

        /* XXX: get_abi relies on the IP ; make sure we set it before we call
         * get_abi */
        s->abi = get_abi(s);

        /* Store arguments in the cross platform/arch struct */
        s->args.a0 = get_reg(&regs, 0, s->abi);
        s->args.a1 = get_reg(&regs, 1, s->abi);
        s->args.a2 = get_reg(&regs, 2, s->abi);
        s->args.a3 = get_reg(&regs, 3, s->abi);
        s->args.a4 = get_reg(&regs, 4, s->abi);
        s->args.a5 = get_reg(&regs, 5, s->abi);
        s->args.sp = regs.TRACY_STACK_POINTER;

        s->args.return_code = regs.TRACY_RETURN_CODE;

        s->type = TRACY_EVENT_SYSCALL;

        /* If we fork, then I can't think of a way to nicely send a pre and post
         * fork event to the user. XXX TODO FIXME */
        check_syscall(s);
        if (tracy_handle_syscall_hook(s)) {
            s->type = TRACY_EVENT_QUIT;
            s->signal_num = SIGKILL;

            return s;
        }

        if (!s->child->denied_nr) {
            if (!tracy_internal_syscall(s)) {
                /* Call hook again. This is a bit hacky, I don't think we want
                 * to do this everywhere. FIXME XXX */

                if (tracy_handle_syscall_hook(s)) {
                    /* TODO: Child got killed. Event type -> quit */
                    s->type = TRACY_EVENT_QUIT;
                    s->signal_num = SIGKILL;

                    return s;
                }
            }
        }
    /* TODO: SIGSTOP-ignore should perhaps also be in this piece of code.
     * TRACE_O_TRACEFORK etc. send a SIGSTOP upon creation of a new
     * child */
    } else if (signal_id == SIGTRAP) {
        PTRACE_CHECK(PTRACE_GETEVENTMSG, pid, NULL, &info, NULL);
        PTRACE_CHECK(PTRACE_GETSIGINFO, pid, NULL, &siginfo, NULL);

        if (siginfo.si_code == SI_KERNEL) {
        } else if (siginfo.si_code <= 0) {
        }

        /* Resume, set signal to 0; we don't want to pass SIGTRAP.
         * TODO: Unless it is sent by userspace? */
#ifdef TRACY_DELIVER_SIGTRAP
        if (t->opt & TRACY_VERBOSE)
            fprintf(stderr, "SIGTRAP from userspace; passing it along\n");
        s->type = TRACY_EVENT_SIGNAL;
        s->signal_num = SIGTRAP;
        return s;
#else
        if (t->opt & TRACY_VERBOSE)
            fprintf(stderr, "SIGTRAP from userspace; suppressing it\n");
        tracy_continue(s, 1);

        goto start;
#endif
        /*return tracy_wait_event(t, c_pid);*/
    } else if (signal_id == SIGSTOP && (t->opt & TRACY_TRACE_CHILDREN) &&
        !(t->opt & TRACY_USE_SAFE_TRACE) && !s->child->received_first_sigstop) {
        /* We ignore the first SIGSTOP signal when
         * PTRACE_O_TRACE{VFORK,FORK,CLONE are used, because on process creation
         * Linux starts the processes with a SIGSTOP signal. From the manpage:
         *
         *    PTRACE_O_TRACEFORK (since Linux 2.5.46)
         *           Stop  the  tracee at the next fork(2) and automatically
         *           start tracing the newly forked process, which will start
         *           with a SIGSTOP.
         */
        if (TRACY_PRINT_SIGNALS(t))
            fprintf(stderr, "SIGSTOP ignored: pid = %d\n", pid);

        s->child->received_first_sigstop = 1;
        tracy_continue(s, 1);
        goto start;
    } else {
        /* Not SIGTRAP, and not the first SIGSTOP signal */
        if (TRACY_PRINT_SIGNALS(t))
            fprintf(stderr, _y("Signal for child: %d")"\n", pid);

        /* Clear siginfo struct */
        memset(&(s->siginfo), 0, sizeof(siginfo_t));

        /* Store signal info in event */
        PTRACE_CHECK(PTRACE_GETSIGINFO, pid, NULL, &(s->siginfo), NULL);

        /* Signal for the child, pass it along. */
        s->signal_num = signal_id;
        s->type = TRACY_EVENT_SIGNAL;

        /* Call signal hook here */
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

