
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <sys/syscall.h>
#include <unistd.h>


int main (int argc, char *argv[]) {
    int child;

    /* If a second argument is given
     * fork by means of clone
     */
    if (argc == 2 && !strcmp("-c", argv[1])) {
        puts("Fork by clone(2)");
        child = fork();
    } else {
        puts("Fork by fork(2)");
        child = syscall(__NR_fork);
    }

    if (child == -1) {
        printf("Fork failed: %d.\n", getpid());
        return EXIT_FAILURE;
    }

    if (child) {
        printf("We are the parent: %d.\n", getpid());
    } else {
        printf("We are the child: %d.\n", getpid());
    }

    return EXIT_SUCCESS;
}
