#define _GNU_SOURCE
#include <string.h>

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#include "tracy.h"
#include "ll.h"

/* For __NR_<SYSCALL> */
#include <sys/syscall.h>
#include <unistd.h>
#include <sys/mman.h>
#include <errno.h>

#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/user.h>

#include <asm/ptrace.h>

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
    pid_t new_pid;

    if (e->child->pre_syscall) {
        tracy_safe_fork(e->child, &new_pid);
    } else {
        printf("POST: Returning...\n");
        return 0;
    }

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
