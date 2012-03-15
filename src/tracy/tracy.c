/*
 * tracy.c: ptrace convenience library
 *
 * TODO:
 *  -   Implement proper failure of ptrace commands handling.
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

#include "ll.h"
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
    /*char proc_mem_path[18];*/

    pid = fork();

    if (t->fpid == 0)
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
        /* TODO: Failure */
        ptrace(PTRACE_KILL, pid, NULL, NULL);
    }

    r = ptrace(PTRACE_SETOPTIONS, pid, NULL, (void*)ptrace_options);
    if (r) {
        ptrace(PTRACE_KILL, pid, NULL, NULL);
        /* TODO: Options may not be supported... Linux 2.4? */
    }

    /* We have made sure we will trace each system call of the child, including
     * the system calls of the children of the child, so the child can now
     * resume. */
    r = ptrace(PTRACE_SYSCALL, pid, NULL, 0);
    if (r) {
        ptrace(PTRACE_KILL, pid, NULL, NULL);
    }

    tc->mem_fd = -1;
    tc->pid = pid;
    tc->pre_syscall = 0;
    tc->inj.injecting = 0;
    tc->inj.cb = NULL;
    tc->denied_nr = 0;

    ll_add(t->childs, tc->pid, tc);
    return tc;
}

static int _tracy_handle_injection(struct tracy_event *e) {
    tracy_hook_func f;

    if (e->child->inj.pre) {
        /* TODO: This probably shouldn't be args.return_code as we're
         * messing with the arguments of the original system call */
        tracy_inject_syscall_pre_post(e->child, &e->args.return_code);
    } else {
        /* TODO: This probably shouldn't be args.return_code as we're
         * messing with the arguments of the original system call */
        tracy_inject_syscall_post_post(e->child, &e->args.return_code);
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
        {0, 0, 0, 0, 0, 0, 0, 0, 0}
    };

/*
 * tracy_wait_event returns an event that is either an event belonging to a
 * child (already allocated) or the none_event (which is also already
 * allocated).
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
            tc->inj.injecting = 0;
            tc->inj.cb = NULL;
            tc->denied_nr = 0;

            ll_add(t->childs, tc->pid, tc);
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

        if (s->child->denied_nr) {
            printf("DENIED SYSTEM CALL: Changing from %s to %s\n",
                    get_syscall_name(regs.TRACY_SYSCALL_REGISTER),
                    get_syscall_name(s->child->denied_nr));
            s->syscall_num = s->child->denied_nr;
            s->args.syscall = s->child->denied_nr;
            s->child->denied_nr = 0;

            /* Args don't matter with denied syscalls */
            s->args.ip = regs.TRACY_IP_REG;
            s->type = TRACY_EVENT_SYSCALL;
            s->args.return_code = regs.TRACY_RETURN_CODE;

            /* TODO: Set ``return code'' for denied system call. Write expects
             * the bytes written for example */

            check_syscall(s);
            return s;
        } else {
            s->args.syscall = regs.TRACY_SYSCALL_REGISTER;
            s->syscall_num = regs.TRACY_SYSCALL_REGISTER;
        }

        s->args.a0 = regs.TRACY_ARG_0;
        s->args.a1 = regs.TRACY_ARG_1;
        s->args.a2 = regs.TRACY_ARG_2;
        s->args.a3 = regs.TRACY_ARG_3;
        s->args.a4 = regs.TRACY_ARG_4;
        s->args.a5 = regs.TRACY_ARG_5;

        s->args.return_code = regs.TRACY_RETURN_CODE;
        s->args.ip = regs.TRACY_IP_REG;

        s->type = TRACY_EVENT_SYSCALL;

        check_syscall(s);

    } else if (signal_id == SIGTRAP) {
        puts("Recursing due to SIGTRAP");

        tracy_continue(s);

        return tracy_wait_event(t);
        /* Continue the child but don't deliver the signal? */
    } else {
        puts("Signal for the child");
        /* Signal for the child, pass it along. */
        s->signal_num = signal_id;
        s->type = TRACY_EVENT_SIGNAL;
    }

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

        s->signal_num = 0; /* Clear signal */
        printf("Passing along signal %d to child %d\n", sig, s->child->pid);
    }

    ptrace(PTRACE_SYSCALL, s->child->pid, NULL, sig);

    return 0;
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
        /* printf("Executing hook for: %s\n", syscall); */
        _hax.pvoid = item->data;
        return _hax.pfunc(e);
    }

    return 1;
}

/* Read a single ``word'' from child e->pid */
int tracy_peek_word(struct tracy_child *child, long from, long *word) {
    errno = 0;

    *word = ptrace(PTRACE_PEEKDATA, child->pid, from, NULL);

    if (errno)
        return -1;

    return 0;
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
ssize_t tracy_read_mem(struct tracy_child *c, void *dest, void *src, size_t n) {
    /* Open memory if it's not open yet */
    if (c->mem_fd < 0) {
        if (open_child_mem(c) < 0)
            return -1;
    }

    /* Try seeking this memory postion */
    if (lseek(c->mem_fd, (off_t)src, SEEK_SET) == (off_t)-1)
        return -1;

    errno = 0;

    /* And read. */
    return read(c->mem_fd, dest, n);
}

int tracy_poke_word(struct tracy_child *child, long to, long word) {
    if (ptrace(PTRACE_POKEDATA, child->pid, to, word)) {
        return -1;
    }

    return 0;
}

ssize_t tracy_write_mem(struct tracy_child *c, void *dest, void *src, size_t n) {
    /* Open memory if it's not open yet */
    if (c->mem_fd < 0) {
        if (open_child_mem(c) < 0)
            return -1;
    }

    /* Try seeking this memory postion */
    if (lseek(c->mem_fd, (off_t)dest, SEEK_SET) == (off_t)-1)
        return -1;

    errno = 0;

    /* And write. */
    return write(c->mem_fd, src, n);
}

/* TODO, rewrite this. */
int tracy_inject_syscall(struct tracy_child *child, long syscall_number,
        struct tracy_sc_args *a, long *return_code) {
    if (child->pre_syscall) {
        /* printf("Calling inject PRE.\n"); */
        /* return tracy_inject_syscall_pre(child, syscall_number, a, return_code); */
        /* TODO */
        printf("WHOOPS PRE, %ld, %ld\n", syscall_number, *return_code & a->return_code);
        return 1;
    } else {
        /* printf("Calling inject POST.\n"); */
        /*return tracy_inject_syscall_post(child, syscall_number, a, return_code);*/
        printf("WHOOPS POST\n");
        return 1;
    }
}

int tracy_inject_syscall_pre_pre(struct tracy_child *child, long syscall_number,
        struct tracy_sc_args *a, tracy_hook_func callback) {

    if (ptrace(PTRACE_GETREGS, child->pid, 0, &child->inj.reg))
        printf("PTRACE_GETREGS failed\n");

    child->inj.cb = callback;
    child->inj.injecting = 1;
    child->inj.pre = 1;
    child->inj.syscall_num = syscall_number;

    if (tracy_modify_syscall(child, syscall_number, a)) {
        printf("tracy_modify_syscall failed\n");
        return 1;
    }

    return 0;
}


int tracy_inject_syscall_pre_post(struct tracy_child *child, long *return_code) {
    int garbage;
    struct TRACY_REGS_NAME newargs;

    if (ptrace(PTRACE_GETREGS, child->pid, 0, &newargs))
        printf("PTRACE_GETREGS failed\n");

    /* printf("Return code of getpid(): %ld\n", newargs.TRACY_RETURN_CODE); */
    *return_code = newargs.TRACY_RETURN_CODE;


    /* POST */
    child->inj.reg.TRACY_IP_REG -= TRACY_SYSCALL_OPSIZE;
    child->inj.reg.TRACY_SYSCALL_N = child->inj.reg.TRACY_SYSCALL_REGISTER;

    if (ptrace(PTRACE_SETREGS, child->pid, 0, &child->inj.reg))
        printf("PTRACE_SETREGS failed\n");

    if (ptrace(PTRACE_SYSCALL, child->pid, NULL, 0))
        printf("PTRACE_SYSCALL failed\n");

    /* Wait for PRE, this shouldn't take long as we literally only wait for
     * the OS to notice that we set the PC back it should give us control back
     * on PRE-syscall*/
    waitpid(child->pid, &garbage, 0);

    return 0;
}

int tracy_inject_syscall_post_pre(struct tracy_child *child, long syscall_number,
        struct tracy_sc_args *a, tracy_hook_func callback) {
    int garbage;
    struct TRACY_REGS_NAME newargs;

    if (ptrace(PTRACE_GETREGS, child->pid, 0, &child->inj.reg))
        printf("PTRACE_GETREGS failed\n");

    child->inj.cb = callback;
    child->inj.injecting = 1;
    child->inj.pre = 0;
    child->inj.syscall_num = syscall_number;

    if (ptrace(PTRACE_GETREGS, child->pid, 0, &newargs))
        printf("PTRACE_GETREGS failed\n");

    /* POST, go back to PRE */
    newargs.TRACY_IP_REG -= TRACY_SYSCALL_OPSIZE;

    if (ptrace(PTRACE_SETREGS, child->pid, 0, &newargs))
        printf("PTRACE_SETREGS failed\n");

    if (ptrace(PTRACE_SYSCALL, child->pid, NULL, 0))
        printf("PTRACE_SYSCALL failed\n");

    /* Wait for PRE, this shouldn't take long as we literally only wait for
     * the OS to notice that we set the PC back it should give us control back
     * on PRE-syscall*/
    waitpid(child->pid, &garbage, 0);

    if (tracy_modify_syscall(child, syscall_number, a)) {
        printf("tracy_modify_syscall failed\n");
        return 1;
    }

    return 0;
}

int tracy_inject_syscall_post_post(struct tracy_child *child, long *return_code) {
    struct TRACY_REGS_NAME newargs;

    if (ptrace(PTRACE_GETREGS, child->pid, 0, &newargs))
        printf("PTRACE_GETREGS failed\n");

    /*printf("Return code of getpid(): %ld\n", newargs.TRACY_RETURN_CODE);*/
    *return_code = newargs.TRACY_RETURN_CODE;

    if (ptrace(PTRACE_SETREGS, child->pid, 0, &child->inj.reg))
        printf("PTRACE_SETREGS failed\n");

    return 0;
}

int tracy_modify_syscall(struct tracy_child *child, long syscall_number,
        struct tracy_sc_args *a) {

    /* change_syscall */
    struct TRACY_REGS_NAME newargs;

    if (ptrace(PTRACE_GETREGS, child->pid, 0, &newargs))
        printf("PTRACE_GETREGS failed\n");

    newargs.TRACY_SYSCALL_REGISTER = syscall_number;
    newargs.TRACY_SYSCALL_N = syscall_number;

    #ifdef __arm__
    ptrace(PTRACE_SET_SYSCALL, child->pid, 0, (void*)syscall_number);
    #endif

    if (a) {
        newargs.TRACY_ARG_1 = a->a1;
        newargs.TRACY_ARG_2 = a->a2;
        newargs.TRACY_ARG_3 = a->a3;
        newargs.TRACY_ARG_4 = a->a4;
        newargs.TRACY_ARG_5 = a->a5;
    }

    if (ptrace(PTRACE_SETREGS, child->pid, 0, &newargs))
        printf("PTRACE_SETREGS failed\n");

    return 0;
}

/*
 * Inject getpid system call, effectivelly rendering the system call useless.
 * TODO: We need to hook into the POST call of this system call, and return a
 * useful value based on the previously called system call.
 * For example, write() returns the number of bytes written.
 */
int tracy_deny_syscall(struct tracy_child* child) {
    int r, nr;

    /* TODO: Set ``return code'' for denied system call. Write expects
     * the bytes written for example. Hook? Sync? (Hook is better) */

    if (!child->pre_syscall) {
        fprintf(stderr, "ERROR: Calling deny on a POST system call");
        return 1;
    }
    nr = child->event.syscall_num;
    r = tracy_modify_syscall(child, __NR_getpid, NULL);
    if (!r)
        child->denied_nr = nr;
    return r;
}
