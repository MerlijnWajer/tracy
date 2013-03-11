#include <stdio.h>

int main() {
    int pid;

    __asm__(
        "syscall"
        :
            "=a"(pid)
        :
            "a"(20)
        );

    printf("Pid: %d\n", pid);

    return 0;
}
