
#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/syscall.h>
#include <sys/user.h>
#include <errno.h>

#include "ll.h"
#include "tracy.h"

int parent_main(pid_t child);
int child_main();

int main()
{
    printf("Any following lines by this program should be double.\n");
    pid_t child = fork();
    if (child) {
        return parent_main(child);
    }

    return child_main();
}

int parent_main(pid_t child)
{
    int status, r;
    struct soxy_ll *l;
    struct soxy_event e;
    struct REGS_NAME regs;

    e.type = EVENT_NONE;

    l = ll_init();
    printf("Hello from parent.\n");
    do {
        r = waitpid(child, &status, 0);
    } while(r == -1 && errno == EINTR);
    ptrace(PTRACE_SETOPTIONS, child, NULL, (void*)OUR_PTRACE_OPTIONS);
    ptrace(PTRACE_SYSCALL, child, NULL, NULL);
    printf("Child traced.\n");

    do {
        wait_for_syscall(l, &e);
        printf("Syscall caught.\n");

        if (e.type == EVENT_SYSCALL_PRE && e.syscall_num == SYS_write) {
            printf("Hai pre.\n");

            ptrace(PTRACE_GETREGS, child, NULL, &regs);

            /* Now let's double this syscall */
            if (inject_syscall(&e))
                perror("inject_syscall");
            ptrace(PTRACE_SETREGS, child, NULL, &regs);

            puts("Do it again.");

            if (inject_syscall(&e))
                perror("inject_syscall");
            ptrace(PTRACE_SETREGS, child, NULL, &regs);

        }
        continue_syscall(&e);
    } while(e.type != EVENT_QUIT);

    return 0;
}

int child_main()
{
    printf("Hello from child.\n");
    ptrace(PTRACE_TRACEME, 0, NULL, NULL);
    printf("Hello from child again.\n");
    /* Wait for parent to catch up */
    raise(SIGTRAP);

    /* Now execute if nothing happened */
    printf("This should be printed twice.\n");
    printf("Hello, double world.\n");

    return 0;
}

