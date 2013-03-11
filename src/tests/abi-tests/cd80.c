#include <stdio.h>

int main() {
    int pid;

    __asm__(
        "int $0x80"
        :
            "=a"(pid)
        :
            "a"(20)
        );

    printf("Pid: %d\n", pid);

    return 0;
}
