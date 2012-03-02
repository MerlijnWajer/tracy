#define _GNU_SOURCE
#include <string.h>

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#include "tracy.h"
#include "ll.h"

int injected = 0;

int foo(struct tracy_event *e) {
    char *str;

    str = NULL;

    if (!e->child->pre_syscall) {
        injected = 0;
        return 1;
    }

    if (injected > 0) {
        /* printf("Not calling injection: injected = %d\n", injected); */
        return 1;
    }

    injected += 1;

    tracy_inject_syscall(e);

    return 0;
}

int main(int argc, char** argv) {
    struct tracy *tracy;
    struct tracy_event *e;

    tracy = tracy_init();

    if (argc < 2) {
        printf("Usage: soxy <program name> <program arguments>\n");
        return EXIT_FAILURE;
    }

    if (tracy_set_hook(tracy, "write", foo)) {
        printf("Failed to hook write syscall.\n");
        return EXIT_FAILURE;
    }

    argv++; argc--;
    if (!fork_trace_exec(tracy, argc, argv)) {
        perror("fork_trace_exec returned NULL");
        return EXIT_FAILURE;
    }

    while (1) {
        e = tracy_wait_event(tracy);

        /* Handle events */

        /* If the (last) child died, break */
        if (e->type == TRACY_EVENT_NONE) {
            /* puts("We're done"); */
            break;
        }

        if (e->type == TRACY_EVENT_SIGNAL) {
            printf("Signal %ld for child %d\n", e->signal_num, e->child->pid);
        }

        if (e->type == TRACY_EVENT_SYSCALL) {
            if (e->child->pre_syscall) {
                /*
                printf("PRE Syscall %s (%ld) requested by child %d, IP: %ld\n",
                    get_syscall_name(e->syscall_num), e->syscall_num,
                    e->child->pid, e->args.ip);
                */
                if (get_syscall_name(e->syscall_num))
                    if(!tracy_execute_hook(tracy,
                                get_syscall_name(e->syscall_num), e)) {
                        check_syscall(e); /* PRE -> POST */
                    }
            } else {
                /*
                printf("POST Syscall %s (%ld) requested by child %d, IP: %ld\n",
                    get_syscall_name(e->syscall_num), e->syscall_num,
                        e->child->pid, e->args.ip);
                */
                if (get_syscall_name(e->syscall_num))
                    tracy_execute_hook(tracy, get_syscall_name(e->syscall_num),
                            e);
            }
        }

        if (e->type == TRACY_EVENT_QUIT) {
            printf("EVENT_QUIT from %d with signal %ld\n", e->child->pid,
                    e->signal_num);
            if (e->child->pid == tracy->fpid) {
                printf("Our first child died.\n");
            }
        }

        tracy_continue(e);
    }

    tracy_free(tracy);

    return 0;
}
