#include <stdio.h>
#include <stdlib.h>

#include "ptracert.h"

int main(int argc, char** argv) {
    struct soxy_event* e = malloc(sizeof(struct soxy_event));
    int r = 0;

    if (argc < 2) {
        printf("Usage: soxy <program name> <program arguments>\n");
        return 1;
    }

    argv++; argc--;
    fork_trace_exec(argc, argv);

    while (1) {
        r = wait_for_syscall(e);

        /* Handle events */

        /* If the (last) child died, break */
        if (e->type.type == EVENT_NONE) {
            /* puts("We're done"); */
            break;
        }

        if (e->type.type == EVENT_SYSCALL) {
            printf("Syscall %d requested by child %d\n", e->syscall_num, e->pid);
        }
    }

    return 0;
}
