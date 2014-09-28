Tracy, a system call tracer and injector
========================================

Presented is a uniform interface to trace the behaviour of programs
by means of the system calls they perform. Tracing by the user is done without
regard to kernel version, operating system or processor architecture.
The interface, called Tracy, provides a means to watch, modify, augment
and restrict program execution in a controlled environment.

If you wish to use Tracy in a project but do not want the project to be
GPL, contact me for possible licensing options.

Currently supported architectures (In decreasing order of testing):

* amd64
* x86
* arm
* ppc32

With support for the following C libraries:

* glibc
* musl


Website
=======

See http://hetgrotebos.org/wiki/Tracy for the homepage.



Examples
========

C API
-----

.. code-block:: C

    #include <stdlib.h>
    #include "tracy.h"

    int hook_write(struct tracy_event * e) {
        if (e->child->pre_syscall) {
            if(e->args.a0 == 1) {
                return TRACY_HOOK_DENY;
            }
        }

        return TRACY_HOOK_CONTINUE;
    }

    int main(int argc, char** argv) {
        struct tracy * tracy;

        tracy = tracy_init(TRACY_TRACE_CHILDREN | TRACY_VERBOSE);

        if (tracy_set_hook(tracy, "write", TRACY_ABI_NATIVE, hook_write)) {
            fprintf(stderr, "Could not hook write\n");
            return EXIT_FAILURE;
        }

        if (argc < 2) {
            printf("Usage: ./example <program-name>\n");
            return EXIT_FAILURE;
        }

        argv++; argc--;

        if (!tracy_exec(tracy, argv)) {
            perror("tracy_exec");
            return EXIT_FAILURE;
        }

        tracy_main(tracy);

        tracy_free(tracy);

        return EXIT_SUCCESS;
    }


Python API
----------

(EXAMPLE OUTDATED)

.. code-block:: python
    
    from pytracy import Tracy, Child, TRACE_CHILDREN
    import sys
    
    
    class Reverser(Tracy):
        """Reverses written data to file descriptors."""
    
        def __init__(self, options=0):
            Tracy.__init__(self, TRACE_CHILDREN | options)
            self.hook('write', self._handle_write)
    
        def _handle_write(self, e, a, pre):
            c = Child.from_event(e)
            if pre and a.a0 in (1, 2):
                buf = c.read(a.a1, a.a2)
                if buf:
                    c.write(a.a1, buf[::-1])
    
    if __name__ == '__main__':
        t = Reverser()
        t.execute(*sys.argv[1:])
        t.main()

.. **

Work In Progress
================

Tracy is still work in progress, although already quite useful for certain
tasks. We're working W^X support for safe tracing with multiple ABIs and
BSD support.
