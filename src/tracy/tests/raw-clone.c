#include <sys/types.h>
#include <sys/syscall.h>
#include <signal.h>
#include <unistd.h>
#include <stdio.h>
#include <sched.h>

pid_t tid;

/* glibc's getpid implements a cache
 * which will cause incorrect results
 * when calling clone(2) directly
 */
static pid_t no_cache_getpid()
{
    pid_t pid;

#if defined(__x86_64__)
    pid = syscall(__NR_getpid);
#elif defined(__i386__)
    __asm__(
        "int $0x80"
        :
            "=a"(pid)
        :
            "a"(__NR_getpid)
        );
#endif

    return pid;
}

/* This application executes a raw clone(2) syscall to study
 * its return values in both parent and child.
 * For now this test is i386 only.
 */
int main()
{
    int rval;
    pid_t pid = 0;
    tid = no_cache_getpid();

    printf("Test initial PID (and TID) is %d\n", tid);

#if defined(__x86_64__)
    rval = syscall(__NR_clone, CLONE_CHILD_CLEARTID|CLONE_CHILD_SETTID|SIGCHLD, 0, &tid);
#elif defined(__i386__)
    __asm__(
        "int $0x80"
        :
            "=a"(rval)
        :
            "a"(__NR_clone),
            /* Same clone arguments as glibc's fork() */
            "b"(CLONE_CHILD_CLEARTID|CLONE_CHILD_SETTID|SIGCHLD),
            "c"(0),     /* Child stack (not necessary for fork) */
            "d"(&tid)   /* Child thread ID pointer */
        );
#endif

    pid = no_cache_getpid();
    printf("In %d return value is: %d\n", pid, rval);
    printf("In %d, TID is: %d\n", pid, tid);

    return 0;
}

