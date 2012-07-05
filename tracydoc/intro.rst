Synopsis
========

.. http://sphinx.pocoo.org/domains.html#the-c-domain

Description
===========

Tracy object
~~~~~~~~~~~~

tracy_init
----------
.. c:function::
    struct tracy *tracy_init(void);

tracy_init creates the tracy record and returns a pointer to this record on
success. Possible options for *opt*:

-   *TRACY_TRACY_CHILDREN* (Trace children of the tracee created with fork,
    vfork or clone.)
-   *TRACY_USE_SAFE_TRACE* (Do not rely on Linux' auto-trace on fork abilities
    and instead use our own safe implementation)

Returns the tracy record created.

tracy_free
----------

.. c:function::
    void tracy_free(struct tracy *t);

tracy_free frees all the data associated with tracy:

-   Any children being traced are either detached (if we attached) or killed
    if tracy started them.

-   Datastructures used internally.

tracy_quit
----------

.. c:function::
    void tracy_quit(struct tracy* t, int exitcode);

tracy_quit frees all the structures, kills or detaches from all the
children and then calls exit() with *exitcode*. Use tracy_free if you want to
gracefully free tracy.

tracy_main
----------

.. c:function::
    int tracy_main(struct tracy *tracy);

tracy_main is a simple tracy-event loop.
Helper for RAD Tracy deployment

fork_trace_exec
---------------

.. c:function::
    struct tracy_child *fork_trace_exec(struct tracy *t, int argc, char **argv);

fork_trace_exec is the function tracy offers to actually start tracing a
process. fork_trace_exec safely forks, asks to be traced in the child and
then executes the given process with possible arguments.

Returns the first tracy_child. You don't really need to store this as each
event will be directly coupled to a child.

tracy_attach
------------

.. c:function::
    struct tracy_child *tracy_attach(struct tracy *t, pid_t pid);

tracy_attach attaches to a running process specified by pid.

Returns the structure of the attached child.

tracy_wait_event
----------------

.. c:function:: struct tracy_event *tracy_wait_event(struct tracy *t, pid_t pid);

tracy_wait_event waits for an event to occur on any child when pid is -1;
else on a specific child.

tracy_wait_event will detect any new children and automatically add them to
the appropriate datastructures.

An *event* is either a signal or a system call. tracy_wait_event populates
events with the right data; arguments; system call number, etc.

Returns an event pointer or NULL.

If NULL is returned, you should probably kill all the children and stop
tracy; NULL indicates something went wrong internally such as the inability
to allocate memory or an unsolvable ptrace error.

tracy_continue
--------------

.. c:function::
    int tracy_continue(struct tracy_event *s, int sigoverride);

tracy_continue continues the execution of the child that owns event *s*.
If the event was caused by a signal to the child, the signal
is passed along to the child, unless *sigoverride* is set to nonzero.

tracy_kill_child
----------------

tracy_kill_child attemps to kill the child *c*; it does so using ptrace with
the PTRACE_KILL argument.

Return 0 upon success, -1 upon failure.

check_syscall
-------------

.. TODO REMOVE?

.. c:function::
    int check_syscall(struct tracy_event *s);

get_syscall_name
----------------

.. c:function::
    char* get_syscall_name(int syscall);

get_signal_name
---------------

.. c:function::
    char* get_signal_name(int signal);

tracy_set_hook
--------------

.. c:function::
    int tracy_set_hook(struct tracy *t, char *syscall, tracy_hook_func func);

tracy_execute_hook
------------------

.. c:function::
    int tracy_execute_hook(struct tracy *t, char *syscall, struct tracy_event *e);

Memory manipulation
~~~~~~~~~~~~~~~~~~~

tracy_peek_word
---------------

.. c:function::
    int tracy_peek_word(struct tracy_child *c, long from, long* word);

tracy_read_mem
--------------

.. c:function::
    ssize_t tracy_read_mem(struct tracy_child *c, tracy_parent_addr_t dest, tracy_child_addr_t src, size_t n);

tracy_poke_word
---------------

.. c:function::
    int tracy_poke_word(struct tracy_child *c, long to, long word);

tracyy_write_mem
----------------

.. c:function::
    ssize_t tracy_write_mem(struct tracy_child *c, tracy_child_addr_t dest,
        tracy_parent_addr_t src, size_t n);

System call injection
~~~~~~~~~~~~~~~~~~~~~

tracy_inject_syscall
--------------------

.. c:function::
    int tracy_inject_syscall(struct tracy_child *child, long syscall_number,
            struct tracy_sc_args *a, long *return_code);

Inject a system call in process defined by tracy_child *child*.
The syscall_number is the number of the system call; use *SYS_foo* or
*__NR_foo* to retrieve these numbers. *a* is a pointer to the system
call arguments. The *return_code* will be set to the return code of the
system call.

Returns 0 on success; -1 on failure.

tracy_inject_syscall_pre_start
------------------------------

.. c:function::
    int tracy_inject_syscall_pre_start(struct tracy_child *child, long syscall_number,
            struct tracy_sc_args *a, tracy_hook_func callback);

Change the system call, its arguments and the other registers to inject
a system call. Doesn't continue the execution of the child.

Call tracy_inject_syscall_pre_end to reset registers and retrieve the return
value.

Returns 0 on success; -1 on failure.

tracy_inject_syscall_pre_end
----------------------------

.. c:function::
    int tracy_inject_syscall_pre_end(struct tracy_child *child, long *return_code);

Call this after having called tracy_inject_syscall_pre_start, tracy_continue
and waitpid on the child. This function will reset the registers to the
proper values and store the return value in *return_code*.

If you use tracy's event structure (you probably do), then you do not need to
call this function. In fact, you shouldn't.

Returns 0 on success; -1 on failure.

tracy_inject_syscall_post_start
-------------------------------

.. c:function::
    int tracy_inject_syscall_post_start(struct tracy_child *child, long syscall_number,
            struct tracy_sc_args *a, tracy_hook_func callback);

Change the system call, its arguments and the other registers to inject
a system call. Doesn't continue the execution of the child.

Call tracy_inject_syscall_post_end to reset registers and retrieve the return
value.

Returns 0 on success; -1 on failure.

tracy_inject_syscall_post_end
-----------------------------

.. c:function::
    int tracy_inject_syscall_post_end(struct tracy_child *child, long *return_code);

Call this after having called tracy_inject_syscall_post_start, tracy_continue
and waitpid on the child. This function will reset the registers to the
proper values and store the return value in *return_code*.

If you use tracy's event structure (you probably do), then you do not need to
call this function. In fact, you shouldn't.

Returns 0 on success; -1 on failure.

tracy_modify_syscall
--------------------

.. c:function::
    int tracy_modify_syscall(struct tracy_child *child, long syscall_number,
            struct tracy_sc_args *a);

This function allows you to change the system call number and arguments of a
paused child. You can use it to change a0..a5, return_code and the ip.
Changing the IP is particularly important when doing system call injection.
Make sure that you set it to the right value when passing args to this
function.

Changes the system call number to *syscall_number* and if *a* is not NULL,
changes the arguments/registers of the system call to the contents of *a*.

Returns 0 on success, -1 on failure.

tracy_deny_syscall
------------------

.. c:function::
    int tracy_deny_syscall(struct tracy_child* child);

tracy_mmap
----------

.. c:function::
    int tracy_mmap(struct tracy_child *child, tracy_child_addr_t *ret,
            tracy_child_addr_t addr, size_t length, int prot, int flags, int fd,
            off_t pgoffset);

tracy_munmap
------------

.. c:function::
    int tracy_munmap(struct tracy_child *child, long *ret,
           tracy_child_addr_t addr, size_t length);


Notes
=====


Bugs
====


Example
=======
