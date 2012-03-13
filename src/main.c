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

int foo(struct tracy_event *e) {
    long mmap_ret;
    int status;
    long ip;
    pid_t child_pid;
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

       printf("mmap addr: %ld\n", mmap_ret);
    } else {
        printf("POST: Returning...\n");
        return 0;
    }

    h4x.foo = I_AM_THE_END_OF_IT_ALL;
    m4x.foo = start_label;

    tracy_write_mem(e->child, (void*) mmap_ret, m4x.bar, h4x.bar - m4x.bar);

    if (ptrace(PTRACE_GETREGS, e->child->pid, 0, &args))
        perror("GETREGS");

    tracy_deny_syscall(e->child);
    ptrace(PTRACE_SYSCALL, e->child->pid, 0, 0);
    puts("DENIED");
    waitpid(e->child->pid, &status, 0);
    puts("AFTER DENIED");

    args.TRACY_SYSCALL_REGISTER = __NR_fork;
    args.TRACY_SYSCALL_N = __NR_fork;

    ip = args.TRACY_IP_REG;
    args.TRACY_IP_REG = mmap_ret;

    if (ptrace(PTRACE_SETREGS, e->child->pid, 0, &args))
        perror("SETREGS");

    puts("POST");

    ptrace(PTRACE_SYSCALL, e->child->pid, 0, 0);
    waitpid(e->child->pid, &status, 0);

    puts("PRE");

    ptrace(PTRACE_SYSCALL, e->child->pid, 0, 0);
    waitpid(e->child->pid, &status, 0);

    puts("POST");

    if (ptrace(PTRACE_GETREGS, e->child->pid, 0, &args_ret))
        perror("GETREGS");

    child_pid = args_ret.TRACY_RETURN_CODE;
    printf("Fork return value: %d\n", child_pid);

    /* Restore parent */
    args.TRACY_IP_REG = ip;

    if (ptrace(PTRACE_SETREGS, e->child->pid, 0, &args))
        perror("SETREGS");

    puts("Done with fork");

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
