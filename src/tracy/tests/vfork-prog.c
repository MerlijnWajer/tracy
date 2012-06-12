
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <sys/types.h>
#include <unistd.h>
#include <errno.h>
#include <sched.h>
#include <signal.h>

static int dat_shared_mem = 0;
static int child_func(void *parg);

int main (int argc, char *argv[]) {
    char *stack = NULL;
    pid_t child;

    if (argc == 2 && !strcmp("-c", argv[1])) {
        /* 64 kiB stack */
        stack = malloc(sizeof(char) * 64 * 1024);

        if (!stack) {
            perror("malloc failed");
            return EXIT_FAILURE;
        }

        /* vfork by means of clone */
        puts("Using clone(2) to vfork");
#if 0
        child = clone(child_func, stack + 64 * 1024, CLONE_VFORK | SIGCHLD, NULL);
#else
        child = clone(child_func, stack + 64 * 1024, CLONE_VFORK, NULL);
#endif
    } else {
        /* vfork by vfork */
        puts("Using vfork(2)");
        child = vfork();
    }

    if (child == -1) {
        fprintf(stderr, "Fork failed: %d: %s\n", getpid(), strerror(errno));
        return EXIT_FAILURE;
    }

    if (child) {
        printf("We are the parent: %d.\n", getpid());
        if (dat_shared_mem)
            puts("Memory was shared");
        else
            puts("Memory was NOT shared");
    } else {
        child_func(NULL);
    }

    return EXIT_SUCCESS;
}


static int child_func(void *parg)
{
    (void)parg;
    printf("We are the child: %d.\n", getpid());
    dat_shared_mem = 42;
    _exit(0);
}

