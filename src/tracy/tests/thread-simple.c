#include "../tracy.h"
#include "../ll.h"

#include <stdio.h>
#include <stdlib.h>

/* For __NR_<SYSCALL> */
#include <sys/syscall.h>
#include <unistd.h>

#define set_hook(NAME) \
    if (tracy_set_hook(tracy, #NAME, hook_##NAME)) { \
        printf("Could not hook "#NAME" syscall\n"); \
        return EXIT_FAILURE; \
    }

int hook_write(struct tracy_event *e) {
    (void) e;
    return TRACY_HOOK_CONTINUE;
}

int main(int argc, char** argv) {
    struct tracy *tracy;

    /* Tracy options */
    /*tracy = tracy_init(TRACY_TRACE_CHILDREN);*/
    tracy = tracy_init(TRACY_TRACE_CHILDREN | TRACY_VERBOSE);

    if (argc < 2) {
        printf("Usage: ./tracy-inject-simple <program-name>\n");
        return EXIT_FAILURE;
    }

    /* Hooks */
    set_hook(write);

    argv++; argc--;

    /* Start child */
    if (!fork_trace_exec(tracy, argc, argv)) {
        perror("fork_trace_exec");
        return EXIT_FAILURE;
    }

    /* Main event-loop */
    tracy_main(tracy);

    tracy_free(tracy);

    return EXIT_SUCCESS;
}
