#include <stdio.h>
#include <stdlib.h>

#include "ptracert.h"
#include "ll.h"

int main(int argc, char** argv) {
    struct soxy_event* e = malloc(sizeof(struct soxy_event));
    int r = 0;
    struct soxy_ll *l = ll_init();

    if (argc < 2) {
        printf("Usage: soxy <program name> <program arguments>\n");
        return 1;
    }

    argv++; argc--;
    fork_trace_exec(argc, argv);

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
            printf("PRE Syscall %d requested by child %d\n", e->syscall_num, e->pid);
        }

        if (e->type == EVENT_SYSCALL_POST) {
            printf("POST Syscall %d requested by child %d\n", e->syscall_num, e->pid);
        }

        continue_syscall(e, 0);
    }

    ll_free(l);

    return 0;
}
