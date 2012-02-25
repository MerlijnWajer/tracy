/*
 *
 * ptracert.c: ptrace convenience library
 *
 */

/* TODO
 * We also need to implement proper register getting and setting. preferrably
 * arch agnostic. (So we need to define a few register names/number per arch in
 * headers)
 * Or just implement each arch in a different file, whatever works.
 *
 * With these registers we can get arguments, so that should be solved too.
 *
 * We probably also need PEEK and POKE to change the argument data. (Remember
 * that we need to change the data being exchanged? Right.)
 *
 * Heh: http://osdir.com/ml/utrace-devel/2009-10/msg00200.html, http://osdir.com/ml/utrace-devel/2009-10/msg00229.html
 * */

#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/user.h>

#include <asm/ptrace.h>

#include <sys/types.h>
#include <unistd.h>

#include <sys/wait.h>
#include <signal.h>

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>

#include <string.h>

#include <sys/syscall.h>

#include "ptracert.h"


#define OUR_PTRACE_OPTIONS PTRACE_O_TRACESYSGOOD | PTRACE_O_TRACEFORK | \
    PTRACE_O_TRACEVFORK | PTRACE_O_TRACECLONE

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
        kill(getpid(), SIGABRT);

        /* Exec here? (move somewhere else?) */
        if (argc == 1) {
            printf("Executing %s without arguments.\n", argv[0]);
            execv(argv[0], argv);
        } else {
            printf("Executing %s with argument: %s\n", argv[0], argv[1]);
            execv(argv[0], argv);
        }

        if(errno == -1) {
            /* TODO: Failure */
        }
    }

    if (pid == -1) {
        /* TODO: Failure */
        return -1;
    }


    /* Parent */

    /* Wait for SIGABRT from the child */
    waitpid(pid, &status, 0);

    signal_id = WSTOPSIG(status);
    if (signal_id != SIGABRT) {
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

int wait_for_syscall(struct soxy_ll *l, struct soxy_event* s) {
    /* This needs a lot of work ... */
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
        if(ptrace_r) {
            /* TODO FAILURE */
        }
        s->syscall_num = regs.SYSCALL_REGISTER;

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

