#define _GNU_SOURCE
#include <string.h>

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#include "tracy.h"
#include "ll.h"

int injected = 0;

int foo(struct soxy_event *e) {
    long len;
    char *str, *stephen;

    str = NULL;

    if (e->type == EVENT_SYSCALL_POST) {
        printf("foo: Post syscall\n");
        printf("Return value: %ld\n", e->args.return_code);
        injected = 0;
        return 1;
    }

    printf("foo: Pre syscall\n");

    printf("foo: In hook for function call \"write\"(%d)\n", e->syscall_num);
    printf("foo: Argument 0 (fd) for write: %ld\n", e->args.a0);
    printf("foo: Argument 1 (str) for write: %ld\n", e->args.a1);
    printf("foo: Argument 2 (len) for write: %ld\n", e->args.a2);


    if (injected != 0) {
        printf("Not calling injection: injected = %d\n", injected);
        return 1;
    }

    injected = 1;

    inject_syscall(e);
    puts("foo: injected syscall.");
    printf("foo-injected: In hook for function call \"write\"(%d)\n", e->syscall_num);
    printf("foo-injected: Argument 0 (fd) for write: %ld\n", e->args.a0);
    printf("foo-injected: Argument 1 (str) for write: %ld\n", e->args.a1);
    printf("foo-injected: Argument 2 (len) for write: %ld\n", e->args.a2);

    return 0;

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
            printf("PRE Syscall %s (%d) requested by child %d, IP: %ld\n",
                get_syscall_name(e->syscall_num), e->syscall_num, e->pid, e->args.ip);
                */
            if (get_syscall_name(e->syscall_num))
                if(!execute_hook(lh, get_syscall_name(e->syscall_num), e)) {
                    ll_del(l, e->pid); /* Remove PRE */
                }
        }

        if (e->type == EVENT_SYSCALL_POST) {
            /*
            printf("POST Syscall %s (%d) requested by child %d, IP: %ld\n",
                get_syscall_name(e->syscall_num), e->syscall_num, e->pid, e->args.ip);
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
