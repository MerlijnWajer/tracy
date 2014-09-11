/*
    This file is part of Tracy.

    Tracy is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    Tracy is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with Tracy.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <unistd.h>
#include <stdio.h>
#include <errno.h>

#include <sys/wait.h>
#include <signal.h>

#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/ptrace.h>
#include <sched.h>

#include "tracy.h"
#include "trampy.h"

/*
 * tracy-safe-fork.c: Tracy mechanism for securily forking
 * a child process without losing a trace on the newly created process.
 *
 */

static void _tracer_fork_signal_handler(int sig, siginfo_t *info, void *uctx)
{
    /* Context useable by setcontext, not of any use for us */
    (void)uctx;

    fprintf(stderr, _y("tracy: Received %s would attach to child %d")"\n",
        get_signal_name(sig),
        info->si_pid);

    /*PTRACE_CHECK_NORETURN(PTRACE_ATTACH, info->si_pid, 0, 0); */
}

/* Safe forking/cloning
 *
 * This function takes over the PRE fase of a child process' fork
 * syscall. It then forks the child in a controlled manor ensuring
 * tracy will be able to trace the forked process.
 * This function returns the pid of the new child in new_child upon success.
 *
 * Upon error the return value will be -1 and errno will be set appropriately.
 *
 * FIXME: This function memleaks a page upon failure in the child atm.
 * TODO: This function needs a lot more error handling than it contains now.
 * FIXME: Due to the PTRACE_CHECK macro's if a ptrace fails, we will not
 * restore the original signal handler for SIGUSR1.
 */
int tracy_safe_fork(struct tracy_child *c, pid_t *new_child)
{
    tracy_child_addr_t mmap_ret;
    int status;
    long ip, orig_syscall, orig_trampy_pid_reg;
    struct TRACY_REGS_NAME args, args_ret;
    const long page_size = sysconf(_SC_PAGESIZE);
    pid_t child_pid;
    struct sigaction act, old_sigusr1, old_sigchld;
    sigset_t set, old_set;
    struct timespec timeout;
    siginfo_t info;
    int is_vforking = 0;

    child_pid = -1;

    tracy_debug_current(c);

/*
    puts("SAFE_FORKING!");
*/
    /* First let's allocate a page in the child which we shall use
     * to write a piece of forkcode (see trampy.c) to.
     */
   tracy_mmap(c, &mmap_ret,
            NULL, page_size,
            PROT_READ | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS,
            -1, 0
            );

    /* I know this is FUBAR, but bear with me
     *
     * Check for an error value in the return code/address.
     */
    if (mmap_ret < ((tracy_child_addr_t)NULL) &&
            mmap_ret > ((tracy_child_addr_t)-4096)) {
        errno = -(long)mmap_ret;
        perror("tracy_mmap");
        return -1;
    }
/*
    printf("mmap addr: %p\n", (void*)mmap_ret);
*/

    /* XXX - Debug
    printf("trampy_get_safe_entry() = %p\ntrampy_get_code_size() = %d\n",
        trampy_get_safe_entry(), trampy_get_code_size());
    */

    /* Write the piece of code to the child process */
    if (tracy_write_mem(c, (void*) mmap_ret,
            trampy_get_safe_entry(),
            trampy_get_code_size()) < 0) {
        perror("tracy_write_mem");
        return -1;
    }

    /* Fetch the registers to store the original forking syscall and more importantly
     * the instruction pointer.
     */
    PTRACE_CHECK(PTRACE_GETREGS, c->pid, 0, &args, -1);

    /* Deny so we can set the IP on the denied post and do our own fork in a
     * controlled environment */
    tracy_deny_syscall(c);
    c->denied_nr = 0;
    PTRACE_CHECK(PTRACE_SYSCALL, c->pid, 0, 0, -1);
/*
    puts("DENIED, in PRE");
*/
    waitpid(c->pid, &status, __WALL);
/*
    puts("AFTER DENIED, entered POST");
*/

    /* Okay, the child is now in POST syscall mode, and it has
     * just executed a bogus syscall (getpid) inserted by deny syscall.
     *
     * Setup a fork syscall and point the processor to the injected code.
     */
    /*
     * XXX: We do not have to modify the syscall NR since we use this function
     * for fork, clone and vfork.
    args.TRACY_SYSCALL_REGISTER = __NR_fork;
    args.TRACY_SYSCALL_N = __NR_fork;
    */
    orig_syscall = args.TRACY_SYSCALL_REGISTER;
    orig_trampy_pid_reg = args.TRAMPY_PID_REG;

    printf(_r("Safe forking syscall"));
#if 0
    /* TODO: Fix for ABI */
    printf(_r("Safe forking syscall:")" "_g("%s")"\n", get_syscall_name(args.TRACY_SYSCALL_REGISTER));
#endif

    /* Check if this is a vfork-type syscall */
    if (orig_syscall == __NR_vfork)
        is_vforking = 1;

    /* Clone can also cause vfork behaviour */

#pragma message "getreg(&args, 0, 0) is abi dependent and wrong"
    if (orig_syscall == __NR_clone && get_reg(&args, 0, 0) & CLONE_VFORK) {
        puts(_b("clone with CLONE_VFORK detected, treating as vfork call"));
        is_vforking = 1;
    }

    /* XXX: TODO: Should we place an ARM PTRACE_SET_SYSCALL here? */

    /* XXX: The IP we store here is the IP in the PRE phase of the parent process.
     * At that moment the IP points to the instruction following de syscall.
     */
    ip = args.TRACY_IP_REG;
    args.TRACY_IP_REG = (long)mmap_ret;

    /*
    printf(_b("Pointer data @ IP 0x%lx: 0x%lx")"\n", ip,  ptrace(PTRACE_PEEKDATA, c->pid, ip, NULL));
    printf(_b("Pointer data @ IP-4 0x%lx: 0x%lx")"\n", ip - 4,  ptrace(PTRACE_PEEKDATA, c->pid, ip - 4, NULL));
    */

    PTRACE_CHECK(PTRACE_SETREGS, c->pid, 0, &args, -1);

/*
    printf("The IP was changed from %p to %p\n", (void*)ip, (void*)mmap_ret);

    puts("POST, Entering PRE");
*/

    PTRACE_CHECK(PTRACE_SYSCALL, c->pid, 0, 0, -1);
    waitpid(c->pid, &status, __WALL);

    /* At this moment the child is in PRE mode in the trampy code,
     * trying to execute a sched_yield, which we shall now make
     * into a fork syscall.
     */
    PTRACE_CHECK(PTRACE_GETREGS, c->pid, 0, &args_ret, -1);
/*
    printf("The IP is now %p\n", (void*)args_ret.TRACY_IP_REG);
    printf("Modifying syscall back to fork\n");
*/

    /* TODO: Replace the following with a single call to
     * tracy_modify_syscall().
     */
    args_ret.TRACY_SYSCALL_REGISTER = orig_syscall;

    /* TODO: Rethink SYSCALL_N */
    args_ret.TRACY_SYSCALL_N = orig_syscall;

    /* This stores our pid in a specific register, which will then be used by
     * the new child to inform us of its existence.
     */
    args_ret.TRAMPY_PID_REG = getpid();

    /* On ARM the syscall number is not included in any register, so we have
     * this special ptrace option to modify the syscall
     */
    #ifdef __arm__
    PTRACE_CHECK(PTRACE_SET_SYSCALL, c->pid, 0, (void*)orig_syscall, -1);
    #endif

    PTRACE_CHECK(PTRACE_SETREGS, c->pid, 0, &args_ret, -1);

/*
    puts("PRE, Entering POST");
*/

    /* Setup the blocking of signals to atomically wait for them after ptrace */
    sigemptyset(&set);
    sigaddset(&set, SIGUSR1);
    sigaddset(&set, SIGCHLD);
    pthread_sigmask(SIG_BLOCK, &set, &old_set);

    /* Finally before we execute an actual fork syscall
     * setup the SIGUSR1 handler which is used by trampy to
     * inform us of vforking children
     */
    act.sa_sigaction = _tracer_fork_signal_handler;
    sigemptyset(&act.sa_mask);
    act.sa_flags = SA_SIGINFO;
    sigaction(SIGUSR1, &act, &old_sigusr1);
    sigaction(SIGCHLD, &act, &old_sigchld);

    /* Now execute the actual fork.
     *
     * Afterwards the parent will immediately come to a halt
     * while the child will wait for us to attach. See 'trampy.c'
     * for more details.
     */
    PTRACE_CHECK(PTRACE_SYSCALL, c->pid, 0, 0, -1);

    /* Now wait for either SIGCHLD from the forker,
     * or SIGUSR1 from the forkee
     */
    /*sigsuspend(&set);*/
    /*pause();*/
    /*sigwait(&set);*/
    /* XXX: The manpage states all threads within the current process must block
     * aforementioned signals, so there might be some trouble caused by using tracy
     * within a multithreaded larger whole. If not all threads block these signals
     * some thread might still handle them before we get to call sigwaitinfo which
     * causes lock-up of this thread in the worst case or otherwise a race condition
     * wherein we never restore the child or the parent in case of vfork().
     */
    while (1) {
        sigwaitinfo(&set, &info);
        /* In case of SIGCHLD the parent or another process might've stopped */
        if (info.si_signo == SIGCHLD && info.si_pid == c->pid) {
            /* The parent has stopped (completed its syscall), in case of vfork
             * this means the vfork failed. If it didn't something that shouldn't
             * happen occurred.
             */
            if (is_vforking) {
                /* FIXME: There must be a more elegant way to handle failure,
                 * which we currently don't do anyway so go.. go.. go..
                 */
                printf(_r("tracy: During vfork(), failure in parent.")"\n");
                child_pid = -1;
                break;
            } else {
                printf(_b("tracy: During fork(), parent returned first.")"\n");
                break;
            }
        }

        /* This is the new child */
        if (info.si_signo == SIGUSR1) {
            printf(_b("Handling SIGUSR1 from process %d, completing safe-fork")
                "\n", info.si_pid);

            /* If we're vforking the parent is now marked frozen */
            if (is_vforking) {
                c->frozen_by_vfork = 1;
                c->orig_trampy_pid_reg = orig_trampy_pid_reg;
                c->orig_pc = ip;
                c->orig_return_code = info.si_pid;
            }

            /* Attach to the new child */
            /*PTRACE_CHECK(PTRACE_ATTACH, info.si_pid, 0, 0, -1);*/
            child_pid = info.si_pid;

            /* Return PID to caller if they're interested. */
            /* XXX: Assignment to child_pid rarely happens, collapse this
             * line with th other somewhere useful.
             */
            if (new_child)
                *new_child = child_pid;
            break;
        }
    }

    /* The trampy register is now restored to the original value */
    args_ret.TRAMPY_PID_REG = orig_trampy_pid_reg;

    /* If we're vforking there is no point in resuming the parent because
     * it is frozen, unless the vfork failed.
     */
    if (!is_vforking || child_pid == -1) {
        waitpid(c->pid, &status, __WALL);

        PTRACE_CHECK(PTRACE_GETREGS, c->pid, 0, &args_ret, -1);

        /*
            printf("The IP is now %p\n", (void*)args_ret.TRACY_IP_REG);
            puts("POST");
        */

        /* FIXME: We don't check if the fork failed
         * which we really should since there is no point in
         * attaching to a failed fork.
         */
        child_pid = args_ret.TRACY_RETURN_CODE;

        /* Return PID to caller if they're interested. */
        if (new_child)
            *new_child = child_pid;

        printf("Fork return value: %d\n", child_pid);

        /* Now point the parent process after the original fork
         * syscall instruction.
         */
        args_ret.TRACY_IP_REG = ip;
        args_ret.TRACY_RETURN_CODE = child_pid;

        PTRACE_CHECK(PTRACE_SETREGS, c->pid, 0, &args_ret, -1);
        printf("Return code set to %d\n", child_pid);

        c->pre_syscall = 0;

        /* TODO Handle possible kill signal from child that might be waiting
         * in the singal set
         */

    } /* End of non-vfork block */

    /* Attach to the new child */
    printf("Attaching to %d...\n", child_pid);

    /* Ptrace guarantees PRE state (? XXX TODO FIXME)*/
    PTRACE_CHECK(PTRACE_ATTACH, child_pid, 0, 0, -1);
    if (waitpid(child_pid, &status, __WALL) == -1) {
        perror("Failure waiting for new child");
    }

/*
    if (ptrace(PTRACE_SETREGS, child_pid, 0, &args))
        perror("SETREGS");
*/

    /* Restore the new child to its original position */
    args.TRACY_IP_REG = ip;
    args.TRACY_RETURN_CODE = 0;

    /* Retrieve stack pointer first.
     * 
     * clone can modify the stack pointer, so the stack pointer
     * needs to be left untouched.
     */
    PTRACE_CHECK(PTRACE_GETREGS, child_pid, 0, &args_ret, -1);
    args.TRACY_STACK_POINTER = args_ret.TRACY_STACK_POINTER;

    /* Now update child registers */
    PTRACE_CHECK(PTRACE_SETREGS, child_pid, 0, &args, -1);

    /* Set enhanced syscall tracing */
    PTRACE_CHECK(PTRACE_SETOPTIONS, child_pid, 0, PTRACE_O_TRACESYSGOOD, -1);

    /* Continue the new child */

    /* PTRACE_CHECK(PTRACE_SYSCALL, child_pid, 0, 0, -1); */

    /* Poll for any remaining SIGUSR1 so this cannot kill us in the
     * original process signal mode.
     */
    timeout.tv_sec = 0;
    timeout.tv_nsec = 0;
    sigdelset(&set, SIGCHLD);
    sigtimedwait(&set, &info, &timeout);

    /* Restore the original signal handlers */
    sigaction(SIGUSR1, &old_sigusr1, NULL);
    sigaction(SIGCHLD, &old_sigchld, NULL);

    /* Restore signal mask settings */
    pthread_sigmask(SIG_SETMASK, &old_set, NULL);

    /* TODO: We should now munmap the pages in both the parent and the child.
     * Unless ofc. we created a thread which shares VM in which case we should
     * munmap only once.
     */

    return 0;
}
