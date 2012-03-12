#include <stdio.h>
#include <sys/syscall.h>
#include <unistd.h>

int main () {
    pid_t pid;
    int foo;
    printf("Hello\n");

    /* pid = fork(); */
    pid = syscall(__NR_fork);

    if (!pid) {
        printf("You should not yet see this\n");
    } else {
        printf("See this first\n");
        wait(&foo);
        printf("Child is dead\n");
    }

    printf("Done\n");
}

