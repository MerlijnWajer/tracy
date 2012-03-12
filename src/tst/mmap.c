#define _GNU_SOURCE
#include <string.h>

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

/* For __NR_<SYSCALL> */
#include <sys/syscall.h>
#include <unistd.h>
#include <sys/mman.h>
#include <errno.h>

int foo() {
    void *child_addr;

    child_addr = mmap(NULL, sysconf(_SC_PAGESIZE),
             PROT_READ, MAP_PRIVATE | MAP_ANON,
             -1, 0
             );

    printf("CHILD MMAP LOLOL: %p\n", child_addr);

    return 0;
}
int main(int argc, char** argv) {
    foo();

    return 0;
}
