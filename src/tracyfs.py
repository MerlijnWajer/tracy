from pytracy import Tracy, Child, TRACE_CHILDREN
import sys


class File:
    def __init__(self, contents):
        self.contents = contents
        self.offset = 0

    def seek(self, offset, mode):
        pass

    def read(self, size):
        buf = self.contents[self.offset:self.offset+size]
        self.offset += len(buf)
        return buf


class TracyFS(Tracy):
    """Tracy Virtual File System."""

    def __init__(self, options=0):
        Tracy.__init__(self, TRACE_CHILDREN | options)
        self.files = {}
        self.fds = {}
        self.event_to_fds = {}

        self.hook('open', self._handle_open)
        self.hook('seek', self._handle_seek)
        self.hook('read', self._handle_read)
        self.hook('close', self._handle_close)

    def add_file(self, fname, contents):
        self.files[fname] = contents

    def get_fd(self):
        for idx, fd in enumerate(self.fds):
            if fd is None:
                return 0x13371337 + idx
        return 0x13371337 + len(self.fds)

    def _handle_open(self, e, a, pre):
        if pre:
            fname = Child.from_event(e).read_string(a.a0)
            if fname in self.files:
                fd = self.get_fd()
                self.fds[fd] = self.files[fname]
                self.event_to_fds[Child.from_event(e)] = fd
        elif Child.from_event(e) in self.event_to_fds:
            fd = self.event_to_fds.pop(Child.from_event(e))
            a.return_code = fd
            Child.from_event(e).modify_regs(a.syscall, a)

    def _handle_seek(self, e, a, pre):
        pass

    def _handle_read(self, e, a, pre):
        print 'read', pre, a.a0
        if not pre and a.a0 in self.fds:
            print a.a0, a.a1, a.a2
            buf = self.fds[a.a0].read(a.a2)
            Child.from_event(e).write(a.a1, buf)
            a.return_code = len(buf)
            Child.from_event(e).modify_regs(a.syscall, a)

    def _handle_close(self, e, a, pre):
        pass

if __name__ == '__main__':
    fs = TracyFS()

    fs.add_file('/tracy/w00p', File('wizz0p'))

    fs.execute(*sys.argv[1:])
    fs.main()
