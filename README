Tracy, a system call tracer and injector
========================================

Presented is a uniform interface to trace the behaviour of programs
by means of the system calls they perform. Tracing by the user is done without
regard to kernel version, operating system or processor architecture.
The interface, called Tracy, provides a means to watch, modify, augment
and restrict program execution in a controlled environment.

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

Work In Progress
================

We're still in the process of moving out files that are no longer
relevant as well as updating our TODO file and documentation.
