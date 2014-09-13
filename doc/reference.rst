API Reference
=============

This section contains documentation on all public functions exported by Tracy.

Tracy instance
~~~~~~~~~~~~~~

A Tracy instance is required for all tracy functions; make sure you
only create and initialise one.
Creating more than one instance in one process
(especially: using them) is madness and should not be done.

.. _rtracy_init:

tracy_init
----------
.. code-block:: c

    struct tracy *tracy_init(long opt);

.. **

tracy_init creates the tracy structure and returns a pointer to this structure
on success. Current possible options for *opt*:

-   *TRACY_TRACY_CHILDREN* (Trace children of the tracee created with fork,
    vfork or clone.)
-   *TRACY_USE_SAFE_TRACE* (Do not rely on Linux' auto-trace on fork abilities
    and instead use our own safe implementation.)
-   *TRACY_MEMORY_FALLBACK* (Use fallback mechanism is fast memory access fails.)
-   *TRACY_VERBOSE*
    (Tracy will be verbose and print information about events and internal
    logic.)
-   *TRACY_VERBOSE_SIGNAL*
    (Tracy will print information relating to signals.)
-   *TRACY_VERBOSE_SYSCALL*
    (Tracy will print information relating to system calls.)


Multiple options can be passed by using the OR operator.

Returns the tracy instance created.

tracy_free
----------

.. code-block:: c

    void tracy_free(struct tracy *t);

.. **

tracy_free frees all the data associated with tracy:

-   Any children being traced are either detached (if we attached) or killed
    if tracy started them.


tracy_quit
----------

.. code-block:: c

    void tracy_quit(struct tracy* t, int exitcode);

tracy_quit frees all the structures, kills or detaches from all the
children and then calls exit() with *exitcode*. Use tracy_free if you want to
gracefully free tracy.

.. _rtracy_main:

tracy_main
----------

.. code-block:: c

    int tracy_main(struct tracy *tracy);

.. **

tracy_main is a simple tracy-event loop.
Helper for RAD Tracy deployment

.. _rtracy_exec:

tracy_exec
---------------

.. code-block:: c

    struct tracy_child *tracy_exec(struct tracy *t, char **argv);

.. **

tracy_exec is the function tracy offers to actually start tracing a
process. tracy_exec safely forks, asks to be traced in the child and
then executes the given process with possible arguments.

Returns the first tracy_child. You don't really need to store this as each
event will be directly coupled to a child.

tracy_attach
------------

.. code-block:: c

    struct tracy_child *tracy_attach(struct tracy *t, pid_t pid);

.. **

tracy_attach attaches to a running process specified by pid.

Returns the structure of the attached child.

Events
~~~~~~

tracy_wait_event
----------------

.. code-block:: c

    struct tracy_event *tracy_wait_event(struct tracy *t, pid_t pid);

.. **

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

.. code-block:: c

    int tracy_continue(struct tracy_event *s, int sigoverride);

.. **

tracy_continue continues the execution of the child that owns event *s*.
If the event was caused by a signal to the child, the signal
is passed along to the child, unless *sigoverride* is set to nonzero.

tracy_kill_child
----------------

tracy_kill_child attemps to kill the child *c*; it does so using ptrace with
the PTRACE_KILL argument.

Return 0 upon success, -1 upon failure.

tracy_detach_child
-------------------

.. code-block:: c

    int tracy_detach_child(struct tracy_child *c);

tracy_detach_child attempts to detach from child *c*.
Returns 0 upon success; -1 upon failure.


get_syscall_name_abi
--------------------

.. code-block:: c

    char* get_syscall_name_abi(int syscall, int abi);

get_syscall_number_abi
----------------------

.. code-block:: c

    char* get_syscall_number_abi(char * syscall, int abi);

get_signal_name
---------------

.. code-block:: c

    char* get_signal_name(int signal);

Hooks
~~~~~

tracy_set_hook
--------------

.. code-block:: c

    int tracy_set_hook(struct tracy *t, char *syscall, long abi, tracy_hook_func func);

.. **

Set the hook for a system call with the given ABI. If you want to hook a system
call on multiple ABIs, you need to call tracy_set_hook for each ABI.
Valid values for *abi* depend on the platform, but **TRACY_ABI_NATIVE** is
always available and is the sane choice unless you are trying to mix several
ABIs.

Hook functions should return:

* TRACY_HOOK_CONTINUE if everything is fine.
* TRACY_HOOK_DETACH_CHILD if the child should be detached.
* TRACY_HOOK_KILL_CHILD if the child should be killed.
* TRACY_HOOK_ABORT if tracy should kill all childs and quit.

Returns 0 on success, -1 on failure.

tracy_set_signal_hook
---------------------

.. code-block:: c

    int tracy_set_signal_hook(struct tracy *t, tracy_hook_func f);

.. **

Set the signal hook. Called on each signal[1].

Returns 0 on success.

[1] Called on every signal that the tracy user should recieve,
the SIGTRAP's from ptrace are not sent, and neither is the first
SIGSTOP.
Possible return values by the tracy_hook_func for the signal:

* TRACY_HOOK_CONTINUE will send the signal and proceed as normal
* TRACY_HOOK_SUPPRESS will not send a signal and process as normal
* TRACY_HOOK_KILL_CHILD if the child should be killed.
* TRACY_HOOK_ABORT if tracy should kill all childs and quit.


tracy_set_default_hook
----------------------

.. code-block:: c

    int tracy_set_default_hook(struct tracy *t, tracy_hook_func f);

.. **

tracy_set_default_hook

Set the default hook. (Called when a syscall occurs and no hook is installed
for the system call. *func* is the function to be set as hook.

Returns 0 on success.


tracy_execute_hook
------------------

.. code-block:: c

    int tracy_execute_hook(struct tracy *t, char *syscall, struct tracy_event *e);

.. **

Returns the return value of the hook. Hooks should return:

* TRACY_HOOK_CONTINUE if everything is fine.
* TRACY_HOOK_DETACH_CHILD if the child should be detached.
* TRACY_HOOK_KILL_CHILD if the child should be killed.
* TRACY_HOOK_ABORT if tracy should kill all childs and quit.
* TRACY_HOOK_NOHOOK is no hook is in place for this system call.


Memory manipulation
~~~~~~~~~~~~~~~~~~~

tracy_read_mem
--------------

.. code-block:: c

    ssize_t tracy_read_mem(struct tracy_child *c, tracy_parent_addr_t dest, tracy_child_addr_t src, size_t n);

.. **

tracy_write_mem
----------------

.. code-block:: c

    ssize_t tracy_write_mem(struct tracy_child *c, tracy_child_addr_t dest, tracy_parent_addr_t src, size_t n);

.. **

System call injection
~~~~~~~~~~~~~~~~~~~~~

tracy_inject_syscall
--------------------

.. code-block:: c

    int tracy_inject_syscall(struct tracy_child *child, long syscall_number, struct tracy_sc_args *a, long *return_code);

.. **

Inject a system call in process defined by tracy_child *child*.
The syscall_number is the number of the system call; use
`get_syscall_number_abi`_ to get the right number.
*a* is a pointer to the system
call arguments. The *return_code* will be set to the return code of the
system call.

Returns 0 on success; -1 on failure.

tracy_inject_syscall_async
--------------------------

.. code-block:: c

    int tracy_inject_syscall_async(struct tracy_child *child, long syscall_number, struct tracy_sc_args *a, tracy_hook_func callback);

.. **

Inject a system call in process defined by tracy_child *child*.
The syscall_number is the number of the system call; use
`get_syscall_number_abi`_ to get the right number.
*a* is a pointer to the system call arguments.

The injection will be asynchronous; meaning that this function will return
before the injection has finished. To be notified when injection has
finished, pass a value other than NULL as *callback*.

System call modification
~~~~~~~~~~~~~~~~~~~~~~~~

tracy_modify_syscall_args
-------------------------

.. code-block:: c

    int tracy_modify_syscall_args(struct tracy_child *child, long syscall_number, struct tracy_sc_args *a);

.. **

This function allows you to change the system call number and arguments of a
paused child. You can use it to change a0..a5

Changes the system call number to *syscall_number* and if *a* is not NULL,
changes the argument registers of the system call to the contents of *a*.

Returns 0 on success, -1 on failure.

tracy_modify_syscall_regs
-------------------------

.. code-block:: c

    int tracy_modify_syscall_regs(struct tracy_child *child, long syscall_number, struct tracy_sc_args *a);

.. **

This function allows you to change the system call number and arguments of a
paused child.
Changes the system call number to *syscall_number* and if *a* is not NULL,
changes the registers of the system call to the contents of *a*. These
registers currently include: ip, sp, return_code.

Changing the IP is particularly important when doing system call injection.
Make sure that you set it to the right value when passing args to this
function.

Returns 0 on success, -1 on failure.


tracy_deny_syscall
------------------

.. code-block:: c

    int tracy_deny_syscall(struct tracy_child* child);

tracy_mmap
----------

.. code-block:: c

    int tracy_mmap(struct tracy_child *child, tracy_child_addr_t *ret, tracy_child_addr_t addr, size_t length, int prot, int flags, int fd, off_t pgoffset);

.. **

tracy_munmap
------------

.. code-block:: c

    int tracy_munmap(struct tracy_child *child, long *ret, tracy_child_addr_t addr, size_t length);

.. **
