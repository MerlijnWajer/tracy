#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>

int main() {
    pid_t t;
    t = getpid();
    printf("t: %d\n", t);
    return 0;
}
