/*
 *
 * ptracert.c: ptrace convenience library
 *
 */

#include <sys/ptrace.h>

#include <sys/types.h>
#include <unistd.h>

#include <sys/wait.h>
#include <signal.h>

#include <stdio.h>
#include <errno.h>

#include "ptracert.h"


#define OUR_PTRACE_OPTIONS PTRACE_O_TRACESYSGOOD | PTRACE_O_TRACEFORK | \
    PTRACE_O_TRACEVFORK | PTRACE_O_TRACECLONE

int fork_and_trace(void) {
    pid_t pid;
    long r;
    int status;
    long ptrace_options = OUR_PTRACE_OPTIONS;
    long signal_id;

    pid = fork();

    /* Child */
    if (pid == 0) {
        r = ptrace(PTRACE_TRACEME, 0, NULL, NULL);
        if (r) {
            /* TODO: Failure */
        }

        /* Give the parent to chance to set some extra tracing options before we
         * restart the child and let it call exec() */
        kill(getpid(), SIGABRT);

        /* Exec here? */

        /* Temporarily hardcoded */
        execl("/bin/ls", "ls", NULL);
        if(errno == -1) {
            /* TODO: Failure */
        }
    }

    if (pid == -1) {
        /* TODO: Failure */
        return -1;
    }


    /* Parent */

    waitpid(pid, &status, 0);

    signal_id = WSTOPSIG(status);
    if (signal_id != SIGABRT) {
        /* w-a-t */
    }

    r = ptrace(PTRACE_SETOPTIONS, pid, NULL, (void*)ptrace_options);
    if (r) {
        ptrace(PTRACE_KILL, pid, NULL, NULL);
        /* TODO: Options may not be supported... Linux 2.4? */
    }

    printf("Restarting the process...\n");

    r = ptrace(PTRACE_SYSCALL, pid, NULL, NULL);
    if (r) {
        ptrace(PTRACE_KILL, pid, NULL, NULL);
    }

    return pid;
}
