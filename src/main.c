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

#ifdef TEST_MMAP
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/user.h>
#endif

#include <asm/ptrace.h>

int count;

int foo_close(struct tracy_event *e) {
    printf("close() from %d\n", e->child->pid);
    return 0;
}

#ifdef TEST_MMAP
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
#endif

#ifdef TEST_SAFE_FORK
int foo(struct tracy_event *e) {
    if (e->child->pre_syscall) {
        tracy_safe_fork(e->child, NULL);
    } else {
        printf("POST: Returning...\n");
        return 0;
    }

    return 0;
}
#else
int foo(struct tracy_event *e) {
    count++;

    if (e->child->inj.injected) {
        if (e->child->inj.pre) {
            /*printf("PRE HEYYEYAAEYAAAEYAEYAA: %ld\n", e->args.return_code);*/
        } else {
            /*printf("POST HEYYEYAAEYAAAEYAEYAA: %ld\n", e->args.return_code);*/
        }

        if (count > 0) {
            count = 0;
            return 0;
        }
    }

    if (e->child->pre_syscall) {
        tracy_inject_syscall_pre_start(e->child, __NR_getpid, NULL, foo);
    } else {
        tracy_inject_syscall_post_start(e->child, __NR_getpid, NULL, foo);
    }

    return 0;
}
#endif

int _setpgid(struct tracy_event *e) {
    struct tracy_sc_args a;

    if (e->child->pre_syscall) {
        tracy_deny_syscall(e->child);
    } else {
        memcpy(&a, &(e->args), sizeof(struct tracy_sc_args));
        a.return_code = -ENOSYS;

        tracy_modify_syscall(e->child, __NR_setpgid, &a);
    }
    printf("%ld -> %ld\n", e->args.a0, e->args.a1);

    return 0;
}

#ifdef TEST_SAFE_FORK
int foo_write(struct tracy_event *e) {
    printf("write(2). pre(%d), from child: %d\n", e->child->pre_syscall,
            e->child->pid);
    /*
    if(e->child->pre_syscall)
        tracy_deny_syscall(e->child);
    */

    return 0;
}
#endif

int main(int argc, char** argv) {
    struct tracy *tracy;
    pid_t pid;

    count = 0;

#ifdef TEST_SAFE_FORK
    tracy = tracy_init(0);
#else
    tracy = tracy_init(TRACY_TRACE_CHILDREN);
#endif

    if (argc < 2) {
        printf("Usage: soxy (<program name> <program arguments>) | (-a <list-of-PIDs>)\n");
        return EXIT_FAILURE;
    }

#ifdef TEST_MMAP
    if (tracy_set_hook(tracy, "mmap2", bar)) {
        printf("Failed to hook mmap2 syscall.\n");
        return EXIT_FAILURE;
    }
#endif

#ifdef TEST_SAFE_FORK
    if (tracy_set_hook(tracy, "fork", foo)) {
        printf("Failed to hook fork syscall.\n");
        return EXIT_FAILURE;
    }

    if (tracy_set_hook(tracy, "write", foo_write)) {
        printf("Failed to hook write syscall.\n");
        return EXIT_FAILURE;
    }

#else
    if (tracy_set_hook(tracy, "write", foo)) {
        printf("Failed to hook write syscall.\n");
        return EXIT_FAILURE;
    }

#endif

    if (tracy_set_hook(tracy, "close", foo_close)) {
        printf("Failed to hook close syscall.\n");
        return EXIT_FAILURE;
    }

    if (tracy_set_hook(tracy, "setpgid", _setpgid)) {
        printf("Failed to hook setpgid syscall.\n");
        return EXIT_FAILURE;
    }

    argv++; argc--;

    /* Check for attaching */
    if (!strcmp(argv[0], "-a")) {
        argc--;
        argv++;

        if (!argc) {
            fprintf(stdout, "Error: -a expects a list of PIDs\n");
            return EXIT_FAILURE;
        }

        /* Process all PIDs passed */
        while (argc) {
            pid = atoi(argv[0]);

            printf("Attaching to %d\n", pid);
            if (!tracy_attach(tracy, pid)) {
                perror("tracy_attach");
                fprintf(stderr, "Couldn't attach to pid %d \"%s\"\n", pid,
                    argv[0]);
                tracy_free(tracy);
                return EXIT_FAILURE;
            }

            argc--;
            argv++;
        }

    /* If not attaching, fork/exec */
    } else if (!tracy_exec(tracy, argc, argv)) {
        perror("tracy_exec returned NULL");
        tracy_free(tracy);
        return EXIT_FAILURE;
    }

    tracy_main(tracy);
    puts("Main loop done.");
    tracy_free(tracy);

    return 0;
}
