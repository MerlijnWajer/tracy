#include <stdio.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

int main () {
    pid_t pid;
    int foo;
    printf("f: Hello\n");

    /* pid = fork(); */
    pid = syscall(__NR_fork);

    if (!pid) {
        printf("f: You should not yet see this\n");
    } else {
        /* sleep(5); */
        printf("f: See this first\n");
        wait(&foo);
        printf("f: Child is dead\n");
    }

    printf("f: Done\n");
}

