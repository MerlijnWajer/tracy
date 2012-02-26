#define _GNU_SOURCE
#include <string.h>

#include <stdio.h>
#include <stdlib.h>

#include "ptracert.h"
#include "ll.h"


int foo(struct soxy_event *e) {
    long len;
    char *str, *stephen;

    str = NULL;

    if (e->type == EVENT_SYSCALL_POST) {
        return 0;

    }

    printf("In hook for function call \"write\"(%d)\n", e->syscall_num);
    printf("Argument 0 (fd) for write: %ld\n", e->args.a0);
    printf("Argument 1 (str) for write: %ld\n", e->args.a1);
    printf("Argument 2 (len) for write: %ld\n", e->args.a2);

    len = e->args.a2;
    str = malloc(sizeof(char) * len);
    read_data(e, e->args.a1, str, sizeof(char) * len);
    printf("Data: %s\n", str);

    stephen = strfry(str);

    /*
    write_data(e, e->args.a1, stephen, sizeof(char) * len);
    */

    /*
     * This will not work, because the child cannot access our memory.
     * SHM?
     */
/*    e->args.a1 = (long)stephen; */

    /* This is allowed, of course */
    e->args.a2 = strlen(stephen);

    printf("Modify_registers: %d.\n", modify_registers(e));

    /* Don't let flushing bully us */
    fflush(NULL);

    return 0;
}

int main(int argc, char** argv) {
    struct soxy_event* e = malloc(sizeof(struct soxy_event));
    int child_pid;
    int r = 0;
    struct soxy_ll *l = ll_init();
    struct soxy_ll *lh = ll_init();

    if (argc < 2) {
        printf("Usage: soxy <program name> <program arguments>\n");
        return 1;
    }

    if (hook_into_syscall(lh, "write", 1, foo)) {
        printf("Failed to hook write syscall.\n");
        return 1;
    }

    argv++; argc--;
    child_pid = fork_trace_exec(argc, argv);

    while (1) {
        r = wait_for_syscall(l, e);

        /* Handle events */

        /* If the (last) child died, break */
        if (e->type == EVENT_NONE) {
            /* puts("We're done"); */
            break;
        }

        if (e->type == EVENT_SIGNAL) {
            printf("Signal %ld for child %d\n", e->signal_num, e->pid);
        }

        if (e->type == EVENT_SYSCALL_PRE) {
            /*
            printf("PRE Syscall %s (%d) requested by child %d\n",
                get_syscall_name(e->syscall_num), e->syscall_num, e->pid);
            */
            if (get_syscall_name(e->syscall_num))
                execute_hook(lh, get_syscall_name(e->syscall_num), e);
        }

        if (e->type == EVENT_SYSCALL_POST) {
            /*
            printf("POST Syscall %s (%d) requested by child %d\n",
                get_syscall_name(e->syscall_num), e->syscall_num, e->pid);
            */
            if (get_syscall_name(e->syscall_num))
                execute_hook(lh, get_syscall_name(e->syscall_num), e);
        }

        if (e->type == EVENT_QUIT) {
            printf("EVENT_QUIT from %d with signal %ld\n", e->pid, e->signal_num);
            if (e->pid == child_pid) {
                printf("Our first child died.\n");
            }
        }

        continue_syscall(e);
    }

    ll_free(l);
    ll_free(lh);

    return 0;
}
