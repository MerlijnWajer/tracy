/*
 *
 * tracy.c: ptrace convenience library
 *
 */

/*
 * TODO: Clean this mess up
 *
 * Heh: http://osdir.com/ml/utrace-devel/2009-10/msg00200.html, http://osdir.com/ml/utrace-devel/2009-10/msg00229.html
 * */

#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/user.h>

#include <asm/ptrace.h>

#include <stdint.h>
#include <sys/types.h>
#include <unistd.h>

#include <sys/wait.h>
#include <signal.h>

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>

#include <string.h>

#include <sys/syscall.h>

#include "tracy.h"

int fork_trace_exec(int argc, char **argv) {
    pid_t pid;
    long r;
    int status;
    long ptrace_options = OUR_PTRACE_OPTIONS;
    long signal_id;

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

        /* Exec here? (move somewhere else?) */
        if (argc == 1) {
            printf("Executing %s without arguments.\n", argv[0]);
            execv(argv[0], argv);
        } else {
            printf("Executing %s with argument: %s\n", argv[0], argv[1]);
            execv(argv[0], argv);
        }

        if (errno == -1) {
            /* TODO: Failure */
        }
    }

    if (pid == -1) {
        /* TODO: Failure */
        return -1;
    }


    /* Parent */

    /* Wait for SIGTRAP from the child */
    waitpid(pid, &status, 0);

    signal_id = WSTOPSIG(status);
    if (signal_id != SIGTRAP) {
        /* w-a-t */
        ptrace(PTRACE_KILL, pid, NULL, NULL);
    }

    r = ptrace(PTRACE_SETOPTIONS, pid, NULL, (void*)ptrace_options);
    if (r) {
        ptrace(PTRACE_KILL, pid, NULL, NULL);
        /* TODO: Options may not be supported... Linux 2.4? */
    }

    /* printf("Resuming the process...\n"); */

    /* We have made sure we will trace each system call of the child, including
     * the system calls of the children of the child, so the child can now
     * resume. */
    r = ptrace(PTRACE_SYSCALL, pid, NULL, 0);
    if (r) {
        ptrace(PTRACE_KILL, pid, NULL, NULL);
    }

    return pid;
}

/*
 *
 */
int wait_for_syscall(struct soxy_ll *l, struct soxy_event* s) {
    int status, signal_id, ptrace_r;
    pid_t pid;
    struct REGS_NAME regs;

    /* ``s'' NEEDS TO BE ALLOCATED IN ADVANCE */
    memset(s, 0, sizeof(struct soxy_event));

    /* Wait for changes */
    pid = waitpid(0, &status, __WALL);


    /* Something went wrong. */
    if (pid == -1) {
        if (errno == EINTR) {

            return -1;
        }

        /* If we were not interrupted, we no longer have any children. */
        s->type = EVENT_NONE;
        return 0;
    }

    s->pid = pid;

    if (!WIFSTOPPED(status)) {
        s->type = EVENT_QUIT;
        if (WIFEXITED(status)) {
            s->signal_num = WEXITSTATUS(status);
        } else if (WIFSIGNALED(status)) {
            s->signal_num = WTERMSIG(status); /* + 128 */
        } else {
            puts("Recursing due to WIFSTOPPED");
            return wait_for_syscall(l, s);
        }
        return 0;
    }

    signal_id = WSTOPSIG(status);

    /*
    Because we set PTRACE_O_TRACESYSGOOD, bit 8 in the signal number is set
    when syscall traps are delivered:

           PTRACE_O_TRACESYSGOOD (since Linux 2.4.6)
             When delivering syscall traps, set bit 7 in the signal number
             (i.e., deliver  (SIGTRAP |  0x80) This makes it easy for the
             tracer to tell the difference between normal traps and those
             caused by a syscall.
             (PTRACE_O_TRACESYSGOOD may not work on all architectures.)
    */

    if (signal_id == (SIGTRAP | 0x80)) {
        /* Make functions to retrieve this */
        ptrace_r = ptrace(PTRACE_GETREGS, pid, NULL, &regs);
        if (ptrace_r) {
            /* TODO FAILURE */
        }
        s->syscall_num = regs.SYSCALL_REGISTER;

        s->args.return_code = regs.SOXY_RETURN_CODE;
        s->args.a0 = regs.SOXY_ARG_0;
        s->args.a1 = regs.SOXY_ARG_1;
        s->args.a2 = regs.SOXY_ARG_2;
        s->args.a3 = regs.SOXY_ARG_3;
        s->args.a4 = regs.SOXY_ARG_4;
        s->args.a5 = regs.SOXY_ARG_5;

        s->args.syscall = regs.SYSCALL_REGISTER;
        s->args.ip = regs.SOXY_IP_REG;

        check_syscall(l, s);

    } else if (signal_id == SIGTRAP) {
        puts("Recursing due to SIGTRAP");

        continue_syscall(s);

        return wait_for_syscall(l, s);
        /* TODO: We shouldn't send SIGTRAP signals:
         * Continue the child but don't deliver the signal? */
    } else {
        puts("Signal for the child");
        /* Signal for the child, pass it along. */
        s->signal_num = signal_id;
        s->type = EVENT_SIGNAL;
    }

    /* TODO TESTING. This probably needs to be somewhere else. */

    return 0;
}

/*
 * This function continues the execution of a process with pid s->pid.
 */
int continue_syscall(struct soxy_event *s) {
    int sig = 0;

    /*  If data is nonzero and not SIGSTOP, it is interpreted as signal to be
     *  delivered to the child; otherwise, no signal is delivered. */
    if (s->type == EVENT_SIGNAL) {
        sig = s->signal_num;
        printf("Passing along signal %d.\n", sig);
    }

    ptrace(PTRACE_SYSCALL, s->pid, NULL, sig);

    return 0;
}

/*
 * Call this function to be able to tell the difference between pre and post
 * system calls. Uses a very simple linked-list. (ll.c)
 */
int check_syscall(struct soxy_ll *l, struct soxy_event *s) {
    struct soxy_ll_item *t;
    if (t = ll_find(l, s->pid)) {
        ll_del(l, s->pid);
        s->type = EVENT_SYSCALL_POST;
    } else {
        ll_add(l, s->pid, NULL);
        s->type = EVENT_SYSCALL_PRE;
    }
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
 *  - We need to disinct between pre and post hooks. The argument is there, it
 *  is just not yet used. (We could store this pre|post int plus the function
 *  pointer in a struct, and put that as void* data instead of just the function
 *  pointer)
 *  - We need to define the return values of the hooks. It should be possible to
 *  block / deny system calls based on the result of the hook. (Right?)
 *
 */
int hook_into_syscall(struct soxy_ll *ll, char *syscall, int pre,
        syscall_hook_func func) {

    struct soxy_ll_item *t;
    int hash;

    hash = hash_syscall(syscall);

    t = ll_find(ll, hash);

    if (!t) {
        if (ll_add(ll, hash, func)) {
            return -1;
            /* Whoops */
        }
    } else {
        return -1;
    }

    return 0;
}

/* Find and execute hook. */
int execute_hook(struct soxy_ll *ll, char *syscall, struct soxy_event *e) {
    struct soxy_ll_item *t;
    int hash;

    syscall_hook_func f = NULL;

    hash = hash_syscall(syscall);

    t = ll_find(ll, hash);

    if (t) {
        f = (syscall_hook_func)(t->data);
        return f(e);
    }

    return 1;
}


/* Read a single ``word'' from child e->pid */
int read_word(struct soxy_event *e, long from, long *word) {
    errno = 0;

    *word = ptrace(PTRACE_PEEKDATA, e->pid, from, NULL);

    if (errno)
        return -1;

    return 0;
}

/* Returns bytes read */
int read_data(struct soxy_event *e, long from, void *to, long size) {
    long offset, leftover, last, rsize;

    /* Round down. */
    rsize = (size / sizeof(long)) * sizeof(long);

    /* Copy, ``word for word'' (that's a joke) */
    for(offset = 0; offset < rsize; offset += sizeof(long))
        if (read_word(e, from + offset, to + offset))
            return 1;

    leftover = size - offset;
    last = 0;
    if (read_word(e, from + offset, &last))
        return offset;

    memcpy(to + offset, &last, leftover);
    return size;
}

int write_word(struct soxy_event *e, long to, long word) {
    if (ptrace(PTRACE_POKEDATA, e->pid, to, word)) {
        return -1;
    }

    return 0;
}

int write_data(struct soxy_event *e, long to, void *from, long size) {
    long offset, leftover, last, rsize;

    /* Round down. */
    rsize = (size / sizeof(long)) * sizeof(long);

    /* Copy, ``word for word'' (that's a joke) */
    for(offset = 0; offset < rsize; offset += sizeof(long))
        if (write_word(e, to + offset, *(long*)(from + offset)))
            return 1;

    leftover = size - offset;

    last = 0;
    /* Retrieve value from ``to''. */
    read_word(e, to + offset, &last);
    /* Only change the part we want to change */
    memcpy(&last, from + offset, leftover);

    if (write_word(e, to + offset, last))
        return offset;

    return size;
}

int modify_registers(struct soxy_event *e) {
    int r;
    struct REGS_NAME regs;

    r = ptrace(PTRACE_GETREGS, e->pid, NULL, &regs);
    if (r)
        return 1;

    regs.SOXY_ARG_0 = e->args.a0;
    regs.SOXY_ARG_1 = e->args.a1;
    regs.SOXY_ARG_2 = e->args.a2;
    regs.SOXY_ARG_3 = e->args.a3;
    regs.SOXY_ARG_4 = e->args.a4;
    regs.SOXY_ARG_5 = e->args.a5;

    regs.SYSCALL_REGISTER = e->args.syscall;
    regs.SOXY_IP_REG = e->args.ip;
    regs.SOXY_RETURN_CODE = e->args.return_code;

    r = ptrace(PTRACE_SETREGS, e->pid, NULL, &regs);

    if (r) {
        printf("SETREGS FAILED\n");
        return 1;
    }

    return 0;
}

/*
 * Currently only doubles
 * Call this in a PRE-event only */
int inject_syscall(struct soxy_event *e) {
    int garbage;
    struct REGS_NAME args, reset_ip;

    ptrace(PTRACE_GETREGS, e->pid, 0, &args);

    continue_syscall(e);

    /* Wait for POST */
    waitpid(e->pid, &garbage, 0);

    /* POST */
    ptrace(PTRACE_GETREGS, e->pid, 0, &reset_ip);
    printf("return value of resumed syscall: %ld\n", reset_ip.SOXY_RETURN_CODE);

    args.SOXY_IP_REG = args.SOXY_IP_REG - 2;
    #ifdef __x86_64__
    args.rax = args.SYSCALL_REGISTER;
    #else
    args.eax = args.SYSCALL_REGISTER;
    #endif
    ptrace(PTRACE_SETREGS, e->pid, 0, &args);

    return 0;
}

