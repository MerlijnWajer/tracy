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
