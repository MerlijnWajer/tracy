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

#ifdef __x86_64__
#include "arch/amd64/syscalls.h"
#endif
#ifdef __i386__
#include "arch/x86/syscalls.h"
#endif
#ifdef __arm__
#include "arch/arm/syscalls.h"
#endif
#ifdef __powerpc__
#include "arch/ppc/syscalls.h"
#endif

/* Foreground PID, used by tracy main's interrupt handler */
static pid_t global_fpid;

struct tracy *tracy_init(long opt) {
    struct tracy *t;

    t = malloc(sizeof(struct tracy));

    if (!t) {
        return NULL;
    }

    t->fpid = 0;

    t->childs = ll_init();
    t->hooks = ll_init();
    t->defhook = NULL;
    t->signal_hook = NULL;

    if (!t->childs || !t->hooks) {
        /* TODO: Does this even work */
        free(t->childs);
        free(t->hooks);
        free(t);
        return NULL;
    }

    /* TODO Check opt for validity */
    t->opt = opt;

    t->defhook = NULL;
    t->signal_hook = NULL;
    t->se.child_create = NULL;

    return t;
}

/* Loop over all child structs in the children list and free them */
static void free_children(struct tracy_ll *children)
{
    struct tracy_child *tc;
    struct tracy_ll_item *cur = children->head;

    /* Walk over all items in the list */
    while(cur) {
        tc = cur->data;

        /* Detach or kill */
        if (tc->attached) {
            fprintf(stderr, _b("Detaching from child %d")"\n", tc->pid);
            /* TODO: What can we do in case of failure? */
            tracy_detach_child(tc);
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
    tc->suppress = 0;
    tc->tracy = t;
    tc->custom = NULL;

    tc->event.child = tc;

    return tc;
}

/* TODO: Environment variables? */
struct tracy_child* tracy_exec(struct tracy *t, char **argv) {
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

        execvp(argv[0], argv);

        if (errno) {
            perror("tracy_exec");
            fprintf(stderr, "execvp failed.\n");
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
        fprintf(stderr, "tracy_exec: child signal was not SIGTRAP.\n");
        kill(pid, SIGKILL);
        waitpid(pid, &status, 0);
        return NULL;
    }

    r = ptrace(PTRACE_SETOPTIONS, pid, NULL, (void*)ptrace_options);
    if (r) {
        fprintf(stderr, "tracy_exec: ptrace(PTRACE_SETOPTIONS) failed.\n");
        kill(pid, SIGKILL);
        waitpid(pid, &status, 0);
        return NULL;
    }

    /* We have made sure we will trace each system call of the child, including
     * the system calls of the children of the child, so the child can now
     * resume. */
    r = ptrace(PTRACE_SYSCALL, pid, NULL, 0);
    if (r) {
        fprintf(stderr, "tracy_exec: ptrace(PTRACE_SYSCALL) failed.\n");
        kill(pid, SIGKILL);
        waitpid(pid, &status, 0);
        return NULL;
    }

    tc = malloc_tracy_child(t, pid);
    if (!tc) {
        fprintf(stderr, "tracy_exec: malloc_tracy_child failed.\n");
        kill(pid, SIGKILL);
        waitpid(pid, &status, 0);
        return NULL;
    }

    /* This child has been created by us - it doesn't get a SIGSTOP that we want
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
    int set_fpid = 0;
    struct tracy_child *tc;

    if ((t->opt & TRACY_TRACE_CHILDREN) && !(t->opt & TRACY_USE_SAFE_TRACE)) {
        ptrace_options |= PTRACE_O_TRACEFORK;
        ptrace_options |= PTRACE_O_TRACEVFORK;
        ptrace_options |= PTRACE_O_TRACECLONE;
    }

    PTRACE_CHECK(PTRACE_ATTACH, pid, NULL, NULL, NULL);

    /* Parent */
    if (t->fpid == 0) {
        t->fpid = pid;
        set_fpid = 1;
    }

    /* Wait for SIGSTOP from the child */
    waitpid(pid, &status, __WALL);

    signal_id = WSTOPSIG(status);
    if (signal_id != SIGSTOP && signal_id != SIGTRAP) {
        fprintf(stderr, "tracy: Error: No SIG(STOP|TRAP), got %s (%ld)\n",
            get_signal_name(signal_id), signal_id);
        /* TODO: Failure */
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
        /* XXX: Need to set errno to something useful */
        if (set_fpid)
            t->fpid = 0;
        return NULL;
    }

    r = ptrace(PTRACE_SETOPTIONS, pid, NULL, (void*)ptrace_options);
    if (r) {
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
        if (set_fpid)
            t->fpid = 0;
        /* TODO: Options may not be supported... Linux 2.4? */
        return NULL;
    }

    /* We have made sure we will trace each system call of the child, including
     * the system calls of the children of the child, so the child can now
     * resume. */
    r = ptrace(PTRACE_SYSCALL, pid, NULL, 0);
    if (r) {
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
        if (set_fpid)
            t->fpid = 0;
        return NULL;
    }

    tc = malloc_tracy_child(t, pid);
    if (!tc) {
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
        if (set_fpid)
            t->fpid = 0;
        return NULL;
    }

    /* This is an attached child */
    tc->attached = 1;
    tc->received_first_sigstop = 0;

    /* XXX: Error handling? */
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

int tracy_detach_child(struct tracy_child *c) {
    /* TODO: Check c->attached value? */
    int c_pid;

    c_pid = c->pid;

    if (c->tracy->opt & TRACY_VERBOSE)
        printf("tracy_detach_child: %d\n", c_pid);

    PTRACE_CHECK_NORETURN(PTRACE_DETACH, c_pid, NULL, NULL);
    if (tracy_remove_child(c)) {
        fprintf(stderr, "tracy_remove_child: Could not remove child %d\n", c_pid);
        return 1;
    }

    return 0;
}

int tracy_kill_child(struct tracy_child *c) {
    if (c->tracy->opt & TRACY_VERBOSE)
        printf("tracy_kill_child: %d\n", c->pid);

    if(kill(c->pid, SIGKILL)) {
        perror("tracy_kill_child: kill");

        return -1;
    }

    if(waitpid(c->pid, NULL, __WALL) < 0) {
        perror("tracy_kill_child: waitpid");

        return -1;
    }

    if (tracy_remove_child(c)) {
        puts("Could not remove child");
        return -1;
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
    struct tracy_ll_item * cur;
    int i = 0;
    cur = t->childs->head;

    while (cur) {
        cur = cur->next;
        i++;
    }

    return i;
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

char* get_syscall_name_abi(int syscall, int abi) {
    int i = 0;

    if (abi < 0 || abi > TRACY_ABI_COUNT) {
        return NULL;
    }

    while (syscalls_abi[abi][i].name) {
        if (syscalls_abi[abi][i].call_nr == syscall)
            return syscalls_abi[abi][i].name;

        i++;
    }

    return NULL;
}

int get_syscall_number(const char *syscall)
{
    int i;
    for (i = 0; syscall_to_string[i].name != NULL; i++) {
        if(!strcmp(syscall_to_string[i].name, syscall)) {
            return syscall_to_string[i].call_nr;
        }
    }
    return -1;
}

int get_syscall_number_abi(const char *syscall, int abi)
{
    int i;

    if (abi < 0 || abi > TRACY_ABI_COUNT) {
        return -1;
    }

    for (i = 0; syscalls_abi[abi][i].name != NULL; i++) {
        if(!strcmp(syscalls_abi[abi][i].name, syscall)) {
            return syscalls_abi[abi][i].call_nr;
        }
    }
    return -1;
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
static int hash_syscall(char * syscall, int abi) {
    int l, v, i;

    l = strlen(syscall);
    if (l < 1)
        return -1;

    v = (int)syscall[0];

    for(i = 0; i < l; i++)
        v = (1000003 * v) ^ (int)syscall[i];
    v = (v << 4) + abi;

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
int tracy_set_hook(struct tracy *t, char *syscall, long abi,
        tracy_hook_func func) {

    struct tracy_ll_item *item;
    int hash;
    union {
            void *pvoid;
            tracy_hook_func pfunc;
        } _hax;

    /* XXX: Do this for each abi in abi_mask */

    hash = hash_syscall(syscall, abi);

    item = ll_find(t->hooks, hash);
    _hax.pfunc = func;

    if (!item) {
        if (ll_add(t->hooks, hash, _hax.pvoid)) {

            /* XXX: Add debug/print here */
            return -1;
        }
    } else {
        /* XXX: Add debug/print here */
        return -1;
    }

    return 0;
}

int tracy_set_signal_hook(struct tracy *t, tracy_hook_func f) {
    t->signal_hook = f;

    return 0;
}

int tracy_set_default_hook(struct tracy *t, tracy_hook_func f) {
    t->defhook = f;

    return 0;
}

/* Find and execute hook. */
int tracy_execute_hook(struct tracy *t, char *syscall, struct tracy_event *e) {
    struct tracy_ll_item *item;
    int hash;
    union {
            void *pvoid;
            tracy_hook_func pfunc;
        } _hax;


    if (TRACY_PRINT_SYSCALLS(t))
        printf(_y("%04d System call: %s (%ld) Pre: %d")"\n",
                e->child->pid, get_syscall_name_abi(e->syscall_num, e->abi),
                e->syscall_num, e->child->pre_syscall);

    hash = hash_syscall(syscall, e->abi);

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

    struct TRACY_REGS_NAME a;
    long abi;

    PTRACE_CHECK(PTRACE_GETREGS, child->pid, 0, &a, -1);

    abi = child->event.abi;

#define __tracy_print_debug(fmt) \
    { \
    printf("DEBUG: 0: %ld 1: %ld 2: %ld 3: %ld 4: %ld 5: %ld" \
            " s: " fmt ", R: " fmt ", PC: " fmt " SP: " fmt "\n", \
            get_reg(&a, 0, abi), get_reg(&a, 1, abi), get_reg(&a, 2, abi), \
            get_reg(&a, 3, abi), get_reg(&a, 4, abi), get_reg(&a, 5, abi), \
            a.TRACY_SYSCALL_REGISTER, a.TRACY_RETURN_CODE, \
            a.TRACY_IP_REG, a.TRACY_STACK_POINTER \
            ); \
    }

#ifdef __arm__
    __tracy_print_debug("%lu");
    __tracy_print_debug("%lx");
#else
#if __GLIBC_MINOR__ <= 15
    __tracy_print_debug("%lu");
    __tracy_print_debug("%lx");
#else
    __tracy_print_debug("%llu");
    __tracy_print_debug("%llx");
#endif /* glibc_minor <= 15 */
#endif /* __arm__ */

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

    /* Setup interrupt handler */
    main_loop_go_on = 1;
    signal(SIGINT, _main_interrupt_handler);

    while (main_loop_go_on) {
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
                fprintf(stderr, _y("Signal %s (%ld) for child %d")"\n",
                    get_signal_name(e->signal_num), e->signal_num, e->child->pid);
            }
        } else

        if (e->type == TRACY_EVENT_SYSCALL) {
            /*
            if (TRACY_PRINT_SYSCALLS(tracy)) {
                printf(_y("%04d System call: %s (%ld) Pre: %d")"\n",
                        e->child->pid, get_syscall_name(e->syscall_num),
                        e->syscall_num, e->child->pre_syscall);
            }
            */
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
            continue;
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

