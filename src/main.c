#define _GNU_SOURCE
#include <string.h>

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#include "tracy.h"
#include "ll.h"

/* For __NR_<SYSCALL> */
#include <sys/syscall.h>

#include <errno.h>


int count;

int foo_close(struct tracy_event *e) {
    printf("close() from %d\n", e->child->pid);
    return 0;
}

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

int main(int argc, char** argv) {
    struct tracy *tracy;

    count = 0;

    tracy = tracy_init(TRACY_TRACE_CHILDREN);

    if (argc < 2) {
        printf("Usage: soxy <program name> <program arguments>\n");
        return EXIT_FAILURE;
    }

    if (tracy_set_hook(tracy, "write", foo)) {
        printf("Failed to hook write syscall.\n");
        return EXIT_FAILURE;
    }

    if (tracy_set_hook(tracy, "close", foo_close)) {
        printf("Failed to hook write syscall.\n");
        return EXIT_FAILURE;
    }

    if (tracy_set_hook(tracy, "setpgid", _setpgid)) {
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
