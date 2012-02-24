#include <stdio.h>

#include "ptracert.h"

int main() {
    fork_and_trace();
    /*
    pid_t child;

    child = fork();
    if(child == 0) {
        ptrace(PTRACE_TRACEME, 0, NULL, NULL);
        execl("/bin/ls", "ls", NULL);
    }
    else {
        wait(NULL);
        orig_eax = ptrace(PTRACE_PEEKUSER,
                          child, 8 * ORIG_RAX,
                          NULL);
        printf("The child made a "
               "system call %ld\n", orig_eax);
        ptrace(PTRACE_CONT, child, NULL, NULL);
    }
    */
    while (1) {
        /* Get syscalls here */

        /* Handle events */

        /* If the child died (and not a child-child), break */
    }
    return 0;
}
