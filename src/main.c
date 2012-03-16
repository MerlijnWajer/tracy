#define _GNU_SOURCE
#include <string.h>

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#include "tracy.h"
#include "ll.h"
#include "trampy.h"

/* For __NR_<SYSCALL> */
#include <sys/syscall.h>
#include <unistd.h>
#include <sys/mman.h>
#include <errno.h>

#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/user.h>

#include <asm/ptrace.h>

pid_t child_pid;

int restore_fork(struct tracy_event *e) {
    struct TRACY_REGS_NAME args;
    puts("RESTORE FORK");
    
    if (e->child->pre_syscall)
        e->child->pre_syscall = 0;
    else
        e->child->pre_syscall = 1;


    printf("pid: %ld\n", e->args.return_code);

    if (ptrace(PTRACE_GETREGS, e->child->pid, 0, &args))
        perror("post getregs");
    args.TRACY_RETURN_CODE = child_pid;
    if (ptrace(PTRACE_SETREGS, e->child->pid, 0, &args))
        perror("post setregs");
    printf("Set return code to %d\n", child_pid);
    return 0;
}

int bar(struct tracy_event *e) {
    struct TRACY_REGS_NAME args;
    ptrace(PTRACE_GETREGS, e->child->pid, 0, &args);

    if (e->child->pre_syscall) {
        printf("Child called mmap\n");
        printf("Args: %ld, %ld, %ld, %ld, %ld, %ld\n",
            args.TRACY_ARG_0,
            args.TRACY_ARG_1,
            args.TRACY_ARG_2,
            args.TRACY_ARG_3,
            args.TRACY_ARG_4,
            args.TRACY_ARG_5);
    } else {
        printf("mmap return value: %ld\n", args.TRACY_RETURN_CODE);
    }

    return 0;
}

int foo(struct tracy_event *e) {
    long mmap_ret;
    int status;
    long ip;
    struct TRACY_REGS_NAME args, args_ret;

    union {
        int (*foo)(void);
        char *bar;
    } h4x, m4x;

    if (e->child->pre_syscall) {
       tracy_mmap(e->child, &mmap_ret,
                NULL, sysconf(_SC_PAGESIZE),
                PROT_READ | PROT_EXEC, MAP_PRIVATE | MAP_ANON,
                -1, 0
                );

        /* I know this is FUBAR, but bear with me */
        if (mmap_ret < 0 && mmap_ret > -4096) {
            errno = -mmap_ret;
            perror("tracy_mmap");
        }
        printf("mmap addr: %p\n", (void*)mmap_ret);
    } else {
        printf("POST: Returning...\n");
        return 0;
    }

    h4x.foo = I_AM_THE_END_OF_IT_ALL;
    m4x.foo = start_label;

    if (tracy_write_mem(e->child, (void*) mmap_ret, m4x.bar, h4x.bar - m4x.bar) < 0)
        perror("tracy_write_mem");

    if (ptrace(PTRACE_GETREGS, e->child->pid, 0, &args))
        perror("GETREGS");

    /* Deny so we can set the IP on the denied post and do our own fork in a
     * controlled environment */
    tracy_deny_syscall(e->child);
    e->child->denied_nr = 0;
    ptrace(PTRACE_SYSCALL, e->child->pid, 0, 0);
    puts("DENIED, in PRE");
    waitpid(e->child->pid, &status, 0);
    puts("AFTER DENIED, entered POST");

    args.TRACY_SYSCALL_REGISTER = __NR_fork;
    args.TRACY_SYSCALL_N = __NR_fork;

    ip = args.TRACY_IP_REG;
    args.TRACY_IP_REG = mmap_ret;

    if (ptrace(PTRACE_SETREGS, e->child->pid, 0, &args))
        perror("SETREGS");

    printf("The IP was changed from %p to %p\n", (void*)ip, (void*)mmap_ret);

    puts("POST, Entering PRE");

    ptrace(PTRACE_SYSCALL, e->child->pid, 0, 0);
    waitpid(e->child->pid, &status, 0);

    /* Since the trampy code modifies the syscall to sched_yield
     * we now need to reset this syscall to fork again.
     */
    if (ptrace(PTRACE_GETREGS, e->child->pid, 0, &args_ret))
        perror("GETREGS");
    printf("The IP is now %p\n", (void*)args_ret.TRACY_IP_REG);
    printf("Modifying syscall back to fork\n");

    args_ret.TRACY_SYSCALL_REGISTER = __NR_fork;
    args_ret.TRACY_SYSCALL_N = __NR_fork;

    #ifdef __arm__
    ptrace(PTRACE_SET_SYSCALL, child->pid, 0, (void*)syscall_number);
    #endif
    if (ptrace(PTRACE_SETREGS, e->child->pid, 0, &args_ret))
        perror("SETREGS");

    puts("PRE, Entering POST");

    ptrace(PTRACE_SYSCALL, e->child->pid, 0, 0);
    waitpid(e->child->pid, &status, 0);

    if (ptrace(PTRACE_GETREGS, e->child->pid, 0, &args_ret))
        perror("GETREGS");
    printf("The IP is now %p\n", (void*)args_ret.TRACY_IP_REG);

    puts("POST");

    if (ptrace(PTRACE_GETREGS, e->child->pid, 0, &args_ret))
        perror("GETREGS");

    child_pid = args_ret.TRACY_RETURN_CODE;
    printf("Fork return value: %d\n", child_pid);

    /* Restore parent */
    args_ret.TRACY_IP_REG = ip;

    if (ptrace(PTRACE_SETREGS, e->child->pid, 0, &args_ret))
        perror("SETREGS");

    tracy_inject_syscall_post_start(e->child, __NR_getpid, NULL, restore_fork);


    printf("Attaching to %d...\n", child_pid);
    ptrace(PTRACE_ATTACH, child_pid, 0, 0);

    /* Wait for child */
    waitpid(child_pid, &status, 0);

    if (ptrace(PTRACE_SETREGS, child_pid, 0, &args))
        perror("SETREGS");

    /* Reset child */
    args.TRACY_IP_REG = ip;
    args.TRACY_RETURN_CODE = 0;

    if (ptrace(PTRACE_SETREGS, child_pid, 0, &args))
        perror("SETREGS");

    ptrace(PTRACE_SETOPTIONS, child_pid, 0, PTRACE_O_TRACESYSGOOD);

    /* Continue child */
    ptrace(PTRACE_SYSCALL, child_pid, 0, 0);

    return 0;
}

int foo_write(struct tracy_event *e) {
    printf("write(2). pre(%d), from child: %d\n", e->child->pre_syscall,
            e->child->pid);
    /*
    if(e->child->pre_syscall)
        tracy_deny_syscall(e->child);
    */

    return 0;
}
int main(int argc, char** argv) {
    struct tracy *tracy;

    tracy = tracy_init();

    if (argc < 2) {
        printf("Usage: soxy <program name> <program arguments>\n");
        return EXIT_FAILURE;
    }

    if (tracy_set_hook(tracy, "fork", foo)) {
        printf("Failed to hook write syscall.\n");
        return EXIT_FAILURE;
    }

    if (tracy_set_hook(tracy, "mmap2", bar)) {
        printf("Failed to hook mmap2 syscall.\n");
        return EXIT_FAILURE;
    }

    if (tracy_set_hook(tracy, "write", foo_write)) {
        printf("Failed to hook write syscall.\n");
        return EXIT_FAILURE;
    }

    argv++; argc--;
    if (!fork_trace_exec(tracy, argc, argv)) {
        perror("fork_trace_exec returned NULL");
        return EXIT_FAILURE;
    }

    tracy_main(tracy);

    tracy_free(tracy);

    return 0;
}
