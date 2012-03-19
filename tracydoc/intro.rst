Synopsis
========

.. http://sphinx.pocoo.org/domains.html#the-c-domain

Description
===========

Tracy object
~~~~~~~~~~~~

tracy_init
----------
.. c:function:: struct tracy *tracy_init(void);

tracy_free
----------

.. c:function:: void tracy_free(struct tracy *t);

tracy_main
----------

.. c:function:: int tracy_main(struct tracy *tracy);

fork_trace_exec
---------------

.. TODO REMOVE?

.. c:function:: struct tracy_child *fork_trace_exec(struct tracy *t, int argc, char **argv);

tracy_wait_event
----------------

.. c:function:: struct tracy_event *tracy_wait_event(struct tracy *t, pid_t pid);

tracy_continue
--------------

.. c:function::
    int tracy_continue(struct tracy_event *s, int sigoverride);

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

tracy_inject_syscall_pre_start
------------------------------

.. c:function::
    int tracy_inject_syscall_pre_start(struct tracy_child *child, long syscall_number,
            struct tracy_sc_args *a, tracy_hook_func callback);

tracy_inject_syscall_pre_end
----------------------------

.. c:function::
    int tracy_inject_syscall_pre_end(struct tracy_child *child, long *return_code);

tracy_inject_syscall_post_start
-------------------------------

.. c:function::
    int tracy_inject_syscall_post_start(struct tracy_child *child, long syscall_number,
            struct tracy_sc_args *a, tracy_hook_func callback);

tracy_inject_syscall_post_end
-----------------------------

.. c:function::
    int tracy_inject_syscall_post_end(struct tracy_child *child, long *return_code);

tracy_modify_syscall
--------------------

.. c:function::
    int tracy_modify_syscall(struct tracy_child *child, long syscall_number,
            struct tracy_sc_args *a);

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
