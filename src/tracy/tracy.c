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

/* Constants */
static const tracy_opcode_t tracy_syscall_magic = TRACY_SC_MAGIC_WORD;

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

    return 0;
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

    r = ptrace(PTRACE_SETREGS, e->pid, NULL, &regs);

    if (r) {
        printf("SETREGS FAILED\n");
        return 1;
    }

    return 0;
}

/* XXX: What should the datatype of the 'word' returned by ptrace be? */

/* Execute system call with current register settings and return upon 
 * completion. This means the type of syscall performed must also
 * have been set upon calling this function.
 *
 * The process must be traced and stopped for this to work.
 *
 * Returns:
 *  -1 on failure, errno will be set to any value ptrace returned.
 *  0 on success.
 *  or, waitpid's status value if the syscall terminated the child.
 */
int inject_syscall(struct soxy_event *e)
{
    int r, status;
    struct REGS_NAME regs;
    tracy_opcode_t original_asm;
    register_t original_ip;

    /* Fetch registers for IP */
    r = ptrace(PTRACE_GETREGS, e->pid, NULL, &regs);
    if (r)
        return -1;

    puts("Got regs");

    original_ip = regs.SOXY_IP_REG;

    /* Push the IP back to word boundry so we can safely store our
     * system call assembly without worrying about alignment.
     */
    regs.SOXY_IP_REG = original_ip & ~(sizeof(tracy_opcode_t) - 1);

    /* Read current assembly at IP */
    errno = 0;
    original_asm = ptrace(PTRACE_PEEKTEXT, e->pid, regs.SOXY_IP_REG, NULL);
    if (errno)
        return -1;
    puts("Got text");

    /* Let's write some shell code */
    r = ptrace(PTRACE_POKETEXT, e->pid, regs.SOXY_IP_REG, &tracy_syscall_magic);
    if (r)
        return -1;
    puts("Written text");

    /* Now setup IP to point to start of syscall magic */
    r = ptrace(PTRACE_SETREGS, e->pid, NULL, &regs);

    /* If this fails that means we've got some serious trouble
     * the assembly is damaged and we cannot modify the IP,
     * kill program and abort..
     *
     * btw, from here on to the point the child is restored to normal
     * operation, any error will be fatal. ;-)
     */
    if (r) {
        perror("ptrace");
        fprintf(stderr, "tracy: FATAL: Cannot modify instruction pointer "
            "in corrupted child process during syscall injection.\n");
        ptrace(PTRACE_KILL, e->pid, NULL, NULL);
        abort();
    }
    puts("Registers in place");

    /* Okay, we're good to go, resume process. */
    ptrace(PTRACE_SYSCALL, e->pid, NULL, NULL);
    puts("Syscall running");

    /* Syscall should be executing by now, let's wait for the child to trap upon
     * leaving the syscall.
     */
    do {
        r = waitpid(e->pid, &status, 0);
    } while (r == -1 && errno == EINTR);
    if (r < 0) {
        perror("ptrace");
        fprintf(stderr, "tracy: FATAL: Wait failure on child with injected "
            "syscall.\n");
        ptrace(PTRACE_KILL, e->pid, NULL, NULL);
        abort();
    }
    puts("Syscall complete");

    /* The syscall might terminate the child,
     * return status in that case.
     */
    if (WIFEXITED(status))
        return status;
    puts("Child did not terminate");

    /* FIXME: I'm now assuming the child is stopped,
     * maybe there need to be some checks here.
     */

    /* Syscall has executed, let's cleanup
     *
     * First restore original assembly */
    r = ptrace(PTRACE_POKETEXT, e->pid, regs.SOXY_IP_REG, &original_asm);
    if (r) {
        perror("ptrace");
        fprintf(stderr, "tracy: FATAL: Cannot restore original assembly "
            "in child.\n");
        ptrace(PTRACE_KILL, e->pid, NULL, NULL);
        abort();
    }
    puts("Assembly restored.");

    /* Secondly restore instruction pointer. */

    /* Fetch registers to keep syscall results */
    r = ptrace(PTRACE_GETREGS, e->pid, NULL, &regs);
    if (r) {
        perror("ptrace");
        fprintf(stderr, "tracy: FATAL: Fetching registers of child with "
            "injected syscall.\n");
        ptrace(PTRACE_KILL, e->pid, NULL, NULL);
        abort();
    }
    puts("Registers read.");

    regs.SOXY_IP_REG = original_ip;

    /* Now write back original IP */
    r = ptrace(PTRACE_SETREGS, e->pid, NULL, &regs);
    if (r) {
        perror("ptrace");
        fprintf(stderr, "tracy: FATAL: Restoring instruction pointer of child "
            "with injected syscall.\n");
        ptrace(PTRACE_KILL, e->pid, NULL, NULL);
        abort();
    }
    puts("Instruction pointer restored.");

    /* That wasn't too hard. :-)
     * Syscall injected and everything back to normal..
     * Well, almost everything.
     */
    return 0;
}

