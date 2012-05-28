
#include <stdio.h>
#include <stdlib.h>

#include <sys/syscall.h>
#include <unistd.h>


int main () {
    int child;

    child = syscall(__NR_fork);

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
