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

#include <stdio.h>
#include <sys/wait.h>
#include <sys/syscall.h>
#include <sys/ptrace.h>

#include "tracy.h"

/*
 * tracy-modification.c: Modification of program behaviour.
 *
 * This includes: Syscall injection, syscall modification and syscall
 * denial.
 */

int tracy_inject_syscall(struct tracy_child *child, long syscall_number,
        struct tracy_sc_args *a, long *return_code) {
    /* We use the async injection functions, but we simply wait() on
     * a specific pid after the first call and then call the async
     * api to finish the injection.
     *
     * We make the distinction between PRE and POST system calls; we have to,
     * they require different injection methods. */

    if (child->pre_syscall) {
        if (tracy_inject_syscall_pre_start(child, syscall_number, a, NULL,
                NULL))
            return -1;

        child->inj.injecting = 0;
        tracy_continue(&child->event, 1);

        waitpid(child->pid, NULL, __WALL);

        return tracy_inject_syscall_pre_end(child, return_code);
    } else {
        if (tracy_inject_syscall_post_start(child, syscall_number, a, NULL,
                NULL))
            return -1;

        child->inj.injecting = 0;

        tracy_continue(&child->event, 1);

        waitpid(child->pid, NULL, __WALL);

        return tracy_inject_syscall_post_end(child, return_code);
    }
}

/* tracy_inject_syscall_pre_start
 *
 * Change the system call, its arguments and the other registers to inject
 * a system call. Doesn't continue the execution of the child.
 *
 * Call tracy_inject_syscall_pre_end to reset registers and retrieve the return
 * value.
 *
 * Returns 0 on success; -1 on failure.
 */
int tracy_inject_syscall_pre_start(struct tracy_child *child, long syscall_number,
        struct tracy_sc_args *a, tracy_hook_func callback, void *data) {
    /* TODO CHECK PRE_SYSCALL BIT */

    PTRACE_CHECK(PTRACE_GETREGS, child->pid, 0, &child->inj.reg, -1);

    child->inj.cb = callback;
    child->inj.injecting = 1;
    child->inj.pre = 1;
    child->inj.syscall_num = syscall_number;
    child->inj.data = data;

    return tracy_modify_syscall(child, syscall_number, a);
}


/*
 * tracy_inject_syscall_pre_end
 *
 * Call this after having called tracy_inject_syscall_pre_start, tracy_continue
 * and waitpid on the child. This function will reset the registers to the
 * proper values and store the return value in *return_code*.
 *
 * If you use tracy's event structure (you probably do), then you do not need to
 * call this function. In fact, you shouldn't.
 *
 * Returns 0 on success; -1 on failure.
 *
 */
int tracy_inject_syscall_pre_end(struct tracy_child *child, long *return_code) {
    struct TRACY_REGS_NAME newargs;

    PTRACE_CHECK(PTRACE_GETREGS, child->pid, 0, &newargs, -1);

    *return_code = newargs.TRACY_RETURN_CODE;

    /* POST */
    child->inj.reg.TRACY_IP_REG -= TRACY_SYSCALL_OPSIZE;

    /* vvvv This is probably not required vvvv */
    child->inj.reg.TRACY_SYSCALL_N = child->inj.reg.TRACY_SYSCALL_REGISTER;

    PTRACE_CHECK(PTRACE_SETREGS, child->pid, 0, &child->inj.reg, -1);

    PTRACE_CHECK(PTRACE_SYSCALL, child->pid, NULL, 0, -1);

    /* Wait for PRE, this shouldn't take long as we literally only wait for
     * the OS to notice that we set the PC back it should give us control back
     * on PRE-syscall. */
    waitpid(child->pid, NULL, __WALL);

    return 0;
}

/* tracy_inject_syscall_post_start
 *
 * Change the system call, its arguments and the other registers to inject
 * a system call. Doesn't continue the execution of the child.
 *
 * Call tracy_inject_syscall_post_end to reset registers and retrieve the return
 * value.
 *
 * Returns 0 on success; -1 on failure.
 */
int tracy_inject_syscall_post_start(struct tracy_child *child, long syscall_number,
        struct tracy_sc_args *a, tracy_hook_func callback, void *data) {
    struct TRACY_REGS_NAME newargs;

    /* TODO CHECK PRE_SYSCALL BIT */
    PTRACE_CHECK(PTRACE_GETREGS, child->pid, 0, &child->inj.reg, -1);

    child->inj.cb = callback;
    child->inj.injecting = 1;
    child->inj.pre = 0;
    child->inj.syscall_num = syscall_number;
    child->inj.data = data;

    PTRACE_CHECK(PTRACE_GETREGS, child->pid, 0, &newargs, -1);

    /* POST, go back to PRE */
    newargs.TRACY_IP_REG -= TRACY_SYSCALL_OPSIZE;

    PTRACE_CHECK(PTRACE_SETREGS, child->pid, 0, &newargs, -1);

    PTRACE_CHECK(PTRACE_SYSCALL, child->pid, NULL, 0, -1);

    /* Wait for PRE, this shouldn't take long as we literally only wait for
     * the OS to notice that we set the PC back; it should give us control back
     * on PRE-syscall*/
    waitpid(child->pid, NULL, __WALL);

    return tracy_modify_syscall(child, syscall_number, a);
}

/*
 * tracy_inject_syscall_post_end
 *
 * Call this after having called tracy_inject_syscall_post_start, tracy_continue
 * and waitpid on the child. This function will reset the registers to the
 * proper values and store the return value in *return_code*.
 *
 * If you use tracy's event structure (you probably do), then you do not need to
 * call this function. In fact, you shouldn't.
 *
 * Returns 0 on success; -1 on failure.
 *
 */
int tracy_inject_syscall_post_end(struct tracy_child *child, long *return_code) {
    struct TRACY_REGS_NAME newargs;

    PTRACE_CHECK(PTRACE_GETREGS, child->pid, 0, &newargs, -1);

    *return_code = newargs.TRACY_RETURN_CODE;

    PTRACE_CHECK(PTRACE_SETREGS, child->pid, 0, &child->inj.reg, -1);

    return 0;
}

/*
 * tracy_modify_syscall
 *
 * This function allows you to change the system call number and arguments of a
 * paused child. You can use it to change a0..a5, return_code and the ip.
 * Changing the IP is particularly important when doing system call injection.
 * Make sure that you set it to the right value when passing args to this
 * function.
 *
 * Changes the system call number to *syscall_number* and if *a* is not NULL,
 * changes the arguments/registers of the system call to the contents of *a*.
 *
 * Returns 0 on success, -1 on failure.
 *
 */
int tracy_modify_syscall(struct tracy_child *child, long syscall_number,
        struct tracy_sc_args *a) {

    /* change_syscall */
    struct TRACY_REGS_NAME newargs;

    PTRACE_CHECK(PTRACE_GETREGS, child->pid, 0, &newargs, -1);

    newargs.TRACY_SYSCALL_REGISTER = syscall_number;
    newargs.TRACY_SYSCALL_N = syscall_number;

    #ifdef __arm__
    /* ARM requires us to call this function to set the system call. */
    PTRACE_CHECK(PTRACE_SET_SYSCALL, child->pid, 0, (void*)syscall_number, -1);
    #endif

    if (a) {
        newargs.TRACY_ARG_0 = a->a0;
        newargs.TRACY_ARG_1 = a->a1;
        newargs.TRACY_ARG_2 = a->a2;
        newargs.TRACY_ARG_3 = a->a3;
        newargs.TRACY_ARG_4 = a->a4;
        newargs.TRACY_ARG_5 = a->a5;
        newargs.TRACY_RETURN_CODE = a->return_code;
        /* XXX For safe fork purposes this line was added
         * changing the IP reg on modify syscall might
         * cause some unexpected behaviour later on.
         */
        newargs.TRACY_IP_REG = a->ip;
    }

    PTRACE_CHECK(PTRACE_SETREGS, child->pid, 0, &newargs, -1);

    return 0;
}

int tracy_deny_syscall(struct tracy_child *child) {
    int r, nr;

    /* TODO: Set ``return code'' for denied system call. Write expects
     * the bytes written for example. This could be done in the POST
     * hook of the denied system call. (Should be done, imho) */

    if (!child->pre_syscall) {
        fprintf(stderr, "ERROR: Calling deny on a POST system call");
        tracy_backtrace();
        return -1;
    }
    nr = child->event.syscall_num;
    r = tracy_modify_syscall(child, __NR_getpid, NULL);
    if (!r)
        child->denied_nr = nr;
    return r;
}

