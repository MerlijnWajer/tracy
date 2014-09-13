API Example
===========

Below are some examples of the Tracy API. If you are looking for the API
reference, skip to the next chapter.

Creating a Tracy instance
-------------------------

.. code-block:: c

    struct tracy *tracy;

    tracy = tracy_init(options);

.. **

Tracy options
~~~~~~~~~~~~~

Tracy has several options that affect the tracing process.
Options are passed to :ref:`rtracy_init` in a bitwise manner.

The following tracy options are available:

- **TRACY_TRACE_CHILDREN**

  If this option is set, tracy will automatically trace all children of the
  process.

- **TRACY_VERBOSE**

  Tracy will be verbose and print information about events and internal logic.

- **TRACY_VERBOSE_SIGNAL**

  Tracy will print information relating to signals.

- **TRACY_VERBOSE_SYSCALL**

  Tracy will print information relating to system calls.

- **TRACY_MEMORY_FALLBACK**

  Enables a ptrace based (slow) memory fallback if the fast memory access
  method is not available.

- **TRACY_USE_SAFE_TRACE**

  Enables experimental tracing of all created children. Instead of relying on
  Linux' mechanism to automatically trace all created children, we utilise our
  own safe tracing mechanism. Theoretically this should also work on BSD
  platforms, but has not yet been tested.

Tracing a process
~~~~~~~~~~~~~~~~~

To start a process, use :ref:`rtracy_exec`. Pass a **NULL** terminated
string array as **argv**.

.. code-block:: c

    int main(int argc, char** argv) {
        struct tracy *tracy;

        tracy = tracy_init(TRACY_TRACE_CHILDREN | TRACY_VERBOSE |
                TRACY_VERBOSE_SIGNAL | TRACY_VERBOSE_SYSCALL);

        if (argc < 2) {
            printf("Usage: ./example <program-name>\n");
            return EXIT_FAILURE;
        }

        argv++; argc--;

        /* Start child */
        if (!tracy_exec(tracy, argc, argv)) {
            perror("tracy_exec");
            return EXIT_FAILURE;
        }

        /* Default event-loop */
        tracy_main(tracy);
    
        /* Free tracy */
        tracy_free(tracy);
    
        return 0;

    }

.. **

Handling Tracy events
---------------------

Generally, you shouldn't care about the specifics of tracy events
and you can just use `tracy_main`_ instead. However, now follows
a quick description of each event in Tracy's event system.

- **TRACY_EVENT_SYSCALL**

    This event indicates that a tracee is trying to perform
    (or has just performed) a system call.

- **TRACY_EVENT_SIGNAL**

    This event indicates that a signal is to be delivered
    to a tracee.

- **TRACY_EVENT_INTERNAL**

    This indicates an internal event in Tracy. This event is used
    in asynchronous system calls and possibly other features in the
    future.

- **TRACY_EVENT_QUIT**

    This indicates that a tracee has been stopped or killed.

- **TRACY_EVENT_NONE**

    A none event is returned on error, or simply when there are no tracees
    left.

tracy_main
~~~~~~~~~~

The :ref:`rtracy_main` procedure is the default way to use Tracy events.
The method does not return until all children have died. It honours the
signal and system call hooks, but does not provide a lot of control over
the event system. If you need more direct control, you could write your own
version of :ref:`rtracy_main`.

Your own event loop
~~~~~~~~~~~~~~~~~~~

A very simple version:

.. code-block:: c

    int tracy_main(struct tracy * tracy) {
        struct tracy_event * e;

        main_loop_go_on = 1;

        while (main_loop_go_on) {
            e = tracy_wait_event(tracy, -1);
            if (!e) {
                fprintf(stderr, "tracy_main: tracy_wait_Event returned NULL\n");
                continue;
            }

            if (e->type == TRACY_EVENT_NONE) {
                break;
            } else if (e->type == TRACY_EVENT_INTERNAL) {
            } else if (e->type == TRACY_EVENT_SIGNAL) {
            } else if (e->type == TRACY_EVENT_SYSCALL) {
            } else if (e->type == TRACY_EVENT_QUIT) {
                printf(_b("EVENT_QUIT from %d with signal %s (%ld)\n"),
                        e->child->pid, get_signal_name(e->signal_num),
                        e->signal_num);
                if (e->child->pid == tracy->fpid) {
                    printf(_g("Our first child died.\n"));
                }

                tracy_remove_child(e->child);
                continue;
            }

            if (!tracy_children_count(tracy)) {
                break;
            }

            tracy_continue(e, 0);
        }

        return 0;
    }


Tracy hooks
-----------

Tracy allows one hooking into any signal sent to a tracee as
well as any system call executed by a tracee.
The return values of the hooks (callbacks) determine the action that
tracy will take.

See `Signal hook`_ and `System call hooks`_ for examples.

Signal hook
~~~~~~~~~~~

Tracy allows hooking into signals as well. One can hook
into any signal to a tracee like this:

.. code-block:: c

    int hook_sig(struct tracy_event * e) {
        if (e->signal_num == SIGTERM) {
            return TRACY_HOOK_SUPPRESS;
        }
        return TRACY_HOOK_CONTINUE;
    }

    struct tracy * t = tracy_init(...);
    tracy_set_signal_hook(t, hook_sig);


System call hooks
~~~~~~~~~~~~~~~~~

.. code-block:: c

    int hook_write(struct tracy_event * e) {
        if (e->child->pre_syscall) {
            printf("Pre-write system call\n");
        } else {
            printf("Pre-write system call\n");
        }
        return TRACY_HOOK_CONTINUE;
    }

    struct tracy * t = tracy_init(...);
    tracy_set_hook(t, "write", TRACY_NATIVE_ABI, hook_write);

Hook return values
~~~~~~~~~~~~~~~~~~

- **TRACY_HOOK_CONTINUE**

    Return this inside a hook when you want the execution to resume normally.

- **TRACY_HOOK_KILL_CHILD**

    Return this inside a hook if you want the child to be killed on hook return.

- **TRACY_HOOK_ABORT**

    Return this to completely kill tracy. Currently tracy will kill all the
    children and then generate a **TRACY_EVENT_NONE**.

    Currently tracy kills its own process as well by calling exit().

- **TRACY_HOOK_SUPPRESS**

    Return this *only* from a signal hook. This will cause the signal that
    would normally be sent to be suppressed instead.

* **TRACY_HOOK_DETACH_CHILD**
  
    Return this if the child should be detached. Only valid for syscall hooks.

- **TRACY_HOOK_DENY**

    Return this **only** from a system call hook. This will cause the
    current system call to be denied.

    The system call will be replaced by a getpid(2) and the return value will
    be set to **-ENOSYS**.

System call modification
------------------------

Changing the arguments
~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: c

    int hook_write(struct tracy_event * e) {
        struct tracy_sc_args a;

        if (e->child->pre_syscall) {
            if (e->args.a0 == 2) {
                memcpy(&a, &(e->args), sizeof(struct tracy_sc_args));
                a.a0 = 1;
                if (tracy_modify_syscall_args(e->child, a.syscall, &a)) {
                    return TRACY_HOOK_ABORT;
                }
            }
        }

        return TRACY_HOOK_CONTINUE;
    }


Denying a system call
~~~~~~~~~~~~~~~~~~~~~

.. code-block:: c

    int hook_write(struct tracy_event * e) {
        if (e->child->pre_syscall) {
            if(e->args.a0 == 1) {
                printf("Denying write to stdout\n");
                return TRACY_HOOK_DENY;
            }

        return TRACY_HOOK_CONTINUE;
    }


System call injection
---------------------

Synchronous injection
~~~~~~~~~~~~~~~~~~~~~

.. code-block:: c

    int _write(struct tracy_event * e) {
        long ret;
        if (tracy_inject_syscall(e->child, get_syscall_number_abi("write", e->abi), &(e->args), &ret))
                return TRACY_HOOK_ABORT;

        printf("Returned: %ld\n", ret);

        return TRACY_HOOK_CONTINUE;
    }

Asynchronous injection
~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: c

    int _write(struct tracy_event * e) {
        if (e->child->inj.injected) {
            printf("We just injected something. Result: %ld\n", e->args.return_code);
            return 0;
        }

        if (tracy_inject_syscall_async(e->child, get_syscall_number_abi("write", e->abi), &(e->args), &_write))
            return TRACY_HOOK_ABORT;

        return TRACY_HOOK_CONTINUE;
    }

Cleaning up
-----------


