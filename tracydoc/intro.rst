Introduction to Tracy
=====================

Tracy is a library written in C that makes it easy to trace and modify system
calls on a UNIX platform. Currently the only supported platform is Linux, but
we're working on supporting other platforms.

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

- *TRACY_TRACE_CHILDREN*

  If this option is set, tracy will automatically trace all children of the
  process.

- *TRACY_VERBOSE*

  Tracy will be verbose and print information about events and internal logic.

- *TRACY_VERBOSE_SIGNAL*

  Tracy will print information relating to signals.

- *TRACY_VERBOSE_SYSCALL*

  Tracy will print information relating to system calls.

- *TRACY_MEMORY_FALLBACK*

  Enable a ptrace based (slow) memory fallback if the fast memory access
  method is not available.

- *TRACY_USE_SAFE_TRACE*

  Enable experimental tracing of all created children; instead of relying on
  Linux' mechanism to automatically tracy all created children, we utilise our
  own safe tracing mechanism. Theoretically this should also work on BSD
  platforms.

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

- *TRACY_EVENT_NONE*

  a

- *TRACY_EVENT_SYSCALL*

  a

- *TRACY_EVENT_SIGNAL*

  a

- *TRACY_EVENT_INTERNAL*

  a

- *TRACY_EVENT_QUIT*

  a

tracy_main
~~~~~~~~~~

The :ref:`rtracy_main` procedure is the default way to use Tracy events.
The method does not return until all children have died. It honours the
signal and system call hooks, but does not provide a lot of control over
the event system. If you need more direct control, you could write your own
version of :ref:`rtracy_main`.

Your own event loop
~~~~~~~~~~~~~~~~~~~

…

Tracy hooks
-----------

Signal hook
~~~~~~~~~~~

System call hooks
~~~~~~~~~~~~~~~~~

Hook return values
~~~~~~~~~~~~~~~~~~


System call modification
------------------------

Changing the arguments
~~~~~~~~~~~~~~~~~~~~~~

Denying a system call
~~~~~~~~~~~~~~~~~~~~~

System call injection
---------------------

Synchronous injection
~~~~~~~~~~~~~~~~~~~~~

Asynchronous injection
~~~~~~~~~~~~~~~~~~~~~~

Cleaning up
-----------

