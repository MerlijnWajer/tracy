#define _GNU_SOURCE
#include <stdio.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

int main () {
    pid_t pid;
    int foo;
    printf("f: Hello\n");

    /* pid = fork(); */
    puts("Executing fork() in a safe environment now");
    pid = syscall(__NR_fork);
    puts("Done with fork in a safe environment... we're free of the endless loop.");

    if (!pid) {
        printf("f: You should not yet see this\n");
    } else {
        /* sleep(5); */
        printf("f: See this first\n");
        wait(&foo);
        printf("f: Child is dead\n");
    }

    printf("f: Done\n");

    return 0;
}

