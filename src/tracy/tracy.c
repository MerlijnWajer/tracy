/*
 * tracy.c: ptrace convenience library
 */

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

struct tracy *tracy_init(void) {
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

    return t;
}

void tracy_free(struct tracy* t) {
    /* TODO: free childs? */

    ll_free(t->hooks);
    ll_free(t->childs);
    free(t);
}

struct tracy_child* fork_trace_exec(struct tracy *t, int argc, char **argv) {
    pid_t pid;
    long r;
    int status;
    long ptrace_options = OUR_PTRACE_OPTIONS;
    long signal_id;
    struct tracy_child *tc;

    pid = fork();

    if (t->fpid != 0)
        t->fpid = pid;

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
            /* printf("Executing %s without arguments.\n", argv[0]); */
            execv(argv[0], argv);
        } else {
            /* printf("Executing %s with argument: %s\n", argv[0], argv[1]); */
            execv(argv[0], argv);
        }

        if (errno == -1) {
            /* TODO: Failure */
        }
    }

    if (pid == -1)
        return NULL;

    tc = malloc(sizeof(struct tracy_child));
    if (!tc) {
        kill(pid, SIGKILL);
        return NULL;
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

    tc->pid = pid;
    tc->pre_syscall = 0; /* Next is pre... */

    ll_add(t->childs, tc->pid, tc);
    return tc;
}

static struct tracy_event none_event = {
        TRACY_EVENT_NONE, NULL, 0, 0,
        {0, 0, 0, 0, 0, 0, 0, 0, 0}
    };
/*
 *
 */
struct tracy_event *tracy_wait_event(struct tracy *t) {
    int status, signal_id, ptrace_r;
    pid_t pid;
    struct TRACY_REGS_NAME regs;
    struct tracy_child *tc;
    struct tracy_event *s;
    struct soxy_ll_item *item;

    s = NULL;

    /* Wait for changes */
    pid = waitpid(0, &status, __WALL);

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
            printf("New child: %d. Adding to tracy...\n", pid);
            tc = malloc(sizeof(struct tracy_child));
            if (!tc) {
                perror("Cannot allocate structure for new child");
                return NULL; /* TODO Kill the child ? */
            }

            tc->pid = pid;
            tc->pre_syscall = 0; /* Next is pre... */

            ll_add(t->childs, tc->pid, tc);
            s = &tc->event;
            s->child = tc;
        } else {
            s = &(((struct tracy_child*)(item->data))->event);
            s->child = item->data;
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
            puts("Recursing due to WIFSTOPPED");
            return tracy_wait_event(t);
        }
        return s;
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
        s->syscall_num = regs.TRACY_SYSCALL_REGISTER;

        s->args.return_code = regs.TRACY_RETURN_CODE;
        s->args.a0 = regs.TRACY_ARG_0;
        s->args.a1 = regs.TRACY_ARG_1;
        s->args.a2 = regs.TRACY_ARG_2;
        s->args.a3 = regs.TRACY_ARG_3;
        s->args.a4 = regs.TRACY_ARG_4;
        s->args.a5 = regs.TRACY_ARG_5;

        s->args.syscall = regs.TRACY_SYSCALL_REGISTER;
        s->args.ip = regs.TRACY_IP_REG;

        s->type = TRACY_EVENT_SYSCALL;

        check_syscall(s);

    } else if (signal_id == SIGTRAP) {
        puts("Recursing due to SIGTRAP");

        tracy_continue(s);

        return tracy_wait_event(t);
        /* TODO: We shouldn't send SIGTRAP signals:
         * Continue the child but don't deliver the signal? */
    } else {
        puts("Signal for the child");
        /* Signal for the child, pass it along. */
        s->signal_num = signal_id;
        s->type = TRACY_EVENT_SIGNAL;
    }
    /* TODO TESTING. This probably needs to be somewhere else. */

    return s;
}

/*
 * This function continues the execution of a process with pid s->pid.
 */
int tracy_continue(struct tracy_event *s) {
    int sig = 0;

    /*  If data is nonzero and not SIGSTOP, it is interpreted as signal to be
     *  delivered to the child; otherwise, no signal is delivered. */
    if (s->type == TRACY_EVENT_SIGNAL) {
        sig = s->signal_num;
        printf("Passing along signal %d.\n", sig);
    }

    ptrace(PTRACE_SYSCALL, s->child->pid, NULL, sig);

    return 0;
}

/*
 * Changes pre/post.
 */
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
        printf("Executing hook for: %s\n", syscall);
        _hax.pvoid = item->data;
        return _hax.pfunc(e);
    }

    return 1;
}

#if 0
/* Read a single ``word'' from child e->pid */
int read_word(struct tracy_event *e, long from, long *word) {
    errno = 0;

    *word = ptrace(PTRACE_PEEKDATA, e->child->pid, from, NULL);

    if (errno)
        return -1;

    return 0;
}

/* Returns bytes read */
int read_data(struct tracy_event *e, long from, void *to, long size) {
    long offset, leftover, last, rsize;

    /* Round down. */
    rsize = (size / sizeof(long));

    /* Copy, ``word for word'' (that's a joke) */
    for(offset = 0; offset < rsize; offset++)
        if (read_word(e, from + offset, (long*)to + offset)))
            return -1;

    leftover = size - offset;
    last = 0;
    if (read_word(e, from + offset, &last))
        return offset;

    memcpy((long*)to + offset, &last, leftover);
    return size;
}

int write_word(struct tracy_event *e, long to, long word) {
    if (ptrace(PTRACE_POKEDATA, e->child->pid, to, word)) {
        return -1;
    }

    return 0;
}

int write_data(struct tracy_event *e, long to, void *from, long size) {
    long offset, leftover, last, rsize;

    /* Round down. */
    rsize = (size / sizeof(long)) * sizeof(long);

    /* Copy, ``word for word'' (that's a joke) */
    for(offset = 0; offset < rsize; offset += sizeof(long))
        if (write_word(e, (char*)to + offset, *(long*)(from + offset)))
            return 1;

    leftover = size - offset;

    last = 0;
    /* Retrieve value from ``to''. */
    read_word(e, (char*)to + offset, &last);
    /* Only change the part we want to change */
    memcpy(&last, from + offset, leftover);

    if (write_word(e, to + offset, last))
        return offset;

    return size;
}
#endif

int modify_registers(struct tracy_event *e) {
    int r;
    struct TRACY_REGS_NAME regs;

    r = ptrace(PTRACE_GETREGS, e->child->pid, NULL, &regs);
    if (r)
        return 1;

    regs.TRACY_ARG_0 = e->args.a0;
    regs.TRACY_ARG_1 = e->args.a1;
    regs.TRACY_ARG_2 = e->args.a2;
    regs.TRACY_ARG_3 = e->args.a3;
    regs.TRACY_ARG_4 = e->args.a4;
    regs.TRACY_ARG_5 = e->args.a5;

    regs.TRACY_SYSCALL_REGISTER = e->args.syscall;
    regs.TRACY_IP_REG = e->args.ip;
    regs.TRACY_RETURN_CODE = e->args.return_code;

    r = ptrace(PTRACE_SETREGS, e->child->pid, NULL, &regs);

    if (r) {
        printf("SETREGS FAILED\n");
        return 1;
    }

    return 0;
}

/* TODO, needs error handling */
int tracy_inject_syscall(struct tracy_event *e) {
    int garbage;
    struct TRACY_REGS_NAME args, newargs;
    struct tracy_event event;

    printf("Injecting getpid() now...\n");

    if (ptrace(PTRACE_GETREGS, e->child->pid, 0, &args))
        printf("PTRACE_GETREGS failed\n");
    if (ptrace(PTRACE_GETREGS, e->child->pid, 0, &newargs))
        printf("PTRACE_GETREGS failed\n");

    event.type = e->type;
    event.child = e->child;
    event.syscall_num = __NR_getpid;
    event.signal_num = 0;
    event.args = e->args;

    newargs.TRACY_SYSCALL_N = event.syscall_num;
    newargs.TRACY_SYSCALL_REGISTER = event.syscall_num;

    if (ptrace(PTRACE_SETREGS, e->child->pid, 0, &newargs))
        printf("ptrace SETREGS failed\n");

    tracy_continue(&event);

    /* Wait for POST */
    waitpid(e->child->pid, &garbage, 0);

    if (ptrace(PTRACE_GETREGS, e->child->pid, 0, &newargs))
        printf("PTRACE_GETREGS failed\n");

    printf("Return code of getpid(): %ld\n", newargs.TRACY_RETURN_CODE);

    /* POST */
    args.TRACY_IP_REG -= TRACY_SYSCALL_OPSIZE;
    args.TRACY_SYSCALL_N = args.TRACY_SYSCALL_REGISTER;

    if (ptrace(PTRACE_SETREGS, e->child->pid, 0, &args))
        printf("PTRACE_SETREGS failed\n");

    tracy_continue(e);

    /* Wait for PRE */
    waitpid(e->child->pid, &garbage, 0);

    return 0;
}

int tracy_modify_syscall() {
    return -1;
}

int tracy_deny_syscall() {
    /* change_syscall */

    tracy_modify_syscall(); /* With __NR_getpid, but make return code 0 or something */

    return -1;
}
