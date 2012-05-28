
#include <stdio.h>
#include <stdlib.h>

#include <sys/types.h>
#include <unistd.h>


int main () {
    pid_t child;

    child = vfork();

    if (child == -1) {
        printf("Fork failed: %d.\n", getpid());
        return EXIT_FAILURE;
    }

    if (child) {
        printf("We are the parent: %d.\n", getpid());
    } else {
        printf("We are the child: %d.\n", getpid());
        _exit(0);
    }

    return EXIT_SUCCESS;
}
