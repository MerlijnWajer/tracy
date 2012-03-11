#define _GNU_SOURCE
#include <string.h>

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#include "tracy.h"
#include "ll.h"

/* For __NR_<SYSCALL> */
#include <sys/syscall.h>


int count;

int foo(struct tracy_event *e) {
    struct tracy_sc_args args;

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
        memcpy(&args, &(e->args), sizeof(struct tracy_sc_args));
        tracy_inject_syscall_pre_start(e->child, __NR_getpid, &args, foo);
    } else {
        memcpy(&args, &(e->args), sizeof(struct tracy_sc_args));
        tracy_inject_syscall_post_start(e->child, __NR_getpid, &args, foo);
    }

    return 0;
}
int main(int argc, char** argv) {
    struct tracy *tracy;
    struct tracy_event *e;

    count = 0;

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
        e = tracy_wait_event(tracy, 0);

        /* Handle events */

        /* If the (last) child died, break */
        if (e->type == TRACY_EVENT_NONE) {
            break;
        } else if (e->type == TRACY_EVENT_INTERNAL) {
            printf("Internal event for syscall: %s\n",
                    get_syscall_name(e->syscall_num));
        }
        if (e->type == TRACY_EVENT_SIGNAL) {
            printf("Signal %ld for child %d\n", e->signal_num, e->child->pid);
        } else

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
        } else

        if (e->type == TRACY_EVENT_QUIT) {
            printf("EVENT_QUIT from %d with signal %ld\n", e->child->pid,
                    e->signal_num);
            if (e->child->pid == tracy->fpid) {
                printf("Our first child died.\n");
            }
        }

        tracy_continue(e, 0);
    }

    tracy_free(tracy);

    return 0;
}
