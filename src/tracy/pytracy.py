"""Python bindings for Tracy."""
import copy
from ctypes import Structure, cdll, POINTER, CFUNCTYPE, cast, byref, sizeof
from ctypes import c_long, c_int, c_void_p, c_byte, c_char_p
from ctypes import create_string_buffer
import sys

# some global linux declarations
PROT_READ = 1
PROT_WRITE = 2
PROT_EXEC = 4

MAP_SHARED = 1
MAP_PRIVATE = 2
MAP_FIXED = 16
MAP_ANONYMOUS = 32


class siginfo_t(Structure):
    _fields_ = [
        ('data', c_byte * 128)
    ]


class SyscallArguments(Structure):
    _fields_ = [
        ('a0', c_long),
        ('a1', c_long),
        ('a2', c_long),
        ('a3', c_long),
        ('a4', c_long),
        ('a5', c_long),
        ('return_code', c_long),
        ('syscall', c_long),
        ('ip', c_long),
        ('sp', c_long),
    ]


class Event(Structure):
    pass


class SpecialEvents(Structure):
    pass


class _Tracy(Structure):
    pass

# http://stackoverflow.com/questions/1405913/
# TODO arm support
if sys.maxsize > 2 ** 32:
    class _Regs(Structure):
        """64bit user_regs_struct is 216 bytes."""
        _fields_ = [
            ('data', c_byte * 216),
        ]
else:
    class _Regs(Structure):
        """32bit user_regs_struct is 68 bytes."""
        _fields_ = [
            ('data', c_byte * 68),
        ]


class InjectData(Structure):
    _fields_ = [
        ('injecting', c_int),
        ('injected', c_int),
        ('pre', c_int),
        ('syscall_num', c_int),
        ('reg', _Regs),
        ('cb', c_void_p),
    ]


class _Child(Structure):
    pass


TRACE_CHILDREN = 1 << 0
VERBOSE = 1 << 1
VERBOSE_SIGNAL = 1 << 2
VERBOSE_SYSCALL = 1 << 3

MEMORY_FALLBACK = 1 << 4
USE_SAFE_TRACE = 1 << 31

EVENT_NONE = 0
EVENT_SYSCALL = 1
EVENT_SIGNAL = 2
EVENT_INTERNAL = 3
EVENT_QUIT = 4

HOOK_CONTINUE = 0
HOOK_KILL_CHILD = 1
HOOK_ABORT = 2
HOOK_NOHOOK = 3
HOOK_SUPPRESS = 4
HOOK_DENY = 5

_hook_func = CFUNCTYPE(c_int, POINTER(Event))
_child_creation = CFUNCTYPE(None, POINTER(_Child))

Event._fields_ = [
    ('typ', c_int),
    ('child', POINTER(_Child)),
    ('syscall_num', c_long),
    ('signal_num', c_long),
    ('args', SyscallArguments),
    ('siginfo', siginfo_t),
]

_Child._fields_ = [
    ('pid', c_int),
    ('attached', c_int),
    ('pre_syscall', c_int),
    ('mem_fd', c_int),
    ('mem_fallback', c_int),
    ('denied_nr', c_int),
    ('suppress', c_int),
    ('custom', c_void_p),
    ('tracy', POINTER(_Tracy)),
    ('inj', InjectData),
    ('frozen_by_fork', c_int),
    ('received_first_sigstop', c_int),
    ('orig_pc', c_long),
    ('orig_trampy_pid_reg', c_long),
    ('orig_return_code', c_long),
    ('event', Event),
]

SpecialEvents._fields_ = [
    ('child_create', _child_creation),
]

_Tracy._fields_ = [
    ('childs', c_void_p),
    ('hooks', c_void_p),
    ('fpid', c_int),
    ('opt', c_long),
    ('defhook', _hook_func),
    ('signal_hook', _hook_func),
    ('se', SpecialEvents),
]


def _set_func(name, restype, *argtypes):
    getattr(_tracy, name).restype = restype
    getattr(_tracy, name).argtypes = argtypes

# TODO improve path support
_tracy = cdll.LoadLibrary('./libtracy.so')
_set_func('tracy_init', POINTER(_Tracy), c_long)
_set_func('tracy_free', None, POINTER(_Tracy))
_set_func('tracy_quit', None, POINTER(_Tracy), c_int)
_set_func('tracy_main', c_int, POINTER(_Tracy))
_set_func('tracy_exec', POINTER(_Child), POINTER(_Tracy), POINTER(c_char_p))
_set_func('tracy_attach', POINTER(_Child), POINTER(_Tracy), c_long)
_set_func('tracy_add_child', POINTER(_Child), POINTER(_Tracy), c_long)
_set_func('tracy_wait_event', POINTER(Event), POINTER(_Tracy), c_long)
_set_func('tracy_continue', c_int, POINTER(Event), c_int)
_set_func('tracy_kill_child', c_int, POINTER(_Child))
_set_func('tracy_remove_child', c_int, POINTER(_Child))
_set_func('tracy_children_count', c_int, POINTER(_Tracy))
_set_func('get_syscall_name', c_char_p, c_int)
_set_func('get_syscall_number', c_int, c_char_p)
_set_func('get_signal_name', c_char_p, c_int)
_set_func('tracy_set_hook', c_int, POINTER(_Tracy), c_char_p, _hook_func)
_set_func('tracy_set_signal_hook', c_int, POINTER(_Tracy), _hook_func)
_set_func('tracy_set_default_hook', c_int, POINTER(_Tracy), _hook_func)
_set_func('tracy_execute_hook', c_int, POINTER(_Tracy), c_char_p,
          POINTER(Event))
_set_func('tracy_read_string', c_char_p, POINTER(_Child), c_void_p)
_set_func('tracy_mmap', c_int, POINTER(_Child), POINTER(c_long), c_long,
          c_long, c_int, c_int, c_int, c_long)
_set_func('tracy_munmap', c_int, POINTER(_Child), POINTER(c_long), c_long,
          c_long)
_set_func('tracy_inject_syscall', c_int, POINTER(_Child), c_long,
          POINTER(SyscallArguments), POINTER(c_long))
_set_func('tracy_inject_syscall_async', c_int, POINTER(_Child), c_long,
          POINTER(SyscallArguments), POINTER(c_long), )
_set_func('tracy_read_mem', c_long, POINTER(_Child), c_long, c_long, c_long)
_set_func('tracy_write_mem', c_long, POINTER(_Child), c_long, c_void_p, c_long)


class Child:
    children = {}

    def __init__(self, tracy, child):
        """Initialize a new Tracy Child."""
        self.tracy = tracy
        self.child = child.contents

        self.children[cast(child, c_void_p).value] = self
        self.gc = None

    @staticmethod
    def from_event(event):
        ptr = cast(event.child, c_void_p).value
        return Child.children[ptr]

    def mmap(self,
             addr=0,
             length=0x1000,
             prot=PROT_READ | PROT_WRITE,
             flags=MAP_PRIVATE | MAP_ANONYMOUS,
             fd=-1,
             offset=0):
        """mmap one or several pages into the child."""
        ret = c_long()
        if _tracy.tracy_mmap(self.child,
                             byref(ret),
                             addr,
                             length,
                             prot,
                             flags,
                             fd,
                             offset) < 0:
            return None
        return ret.value

    def munmap(self, addr, length=0x1000):
        """munmap one or several pages of the child."""
        ret = c_long()
        if _tracy.tracy_munmap(self.child, byref(ret), addr, length) < 0:
            return None
        return ret.value

    def read(self, addr, length):
        """Read memory from the Child process."""
        ret = create_string_buffer(length)
        if _tracy.tracy_read_mem(self.child, byref(ret), addr, length) < 0:
            return None
        return ret.raw

    def read_string(self, addr):
        """Read a nil-terminated string from the Child process."""
        return _tracy.tracy_read_string(self.child, addr)

    def write(self, addr, value):
        """Write data to the Child process."""
        return _tracy.tracy_write_mem(self.child, addr, value, len(value))

    def inject(self, syscall_number, args, callback=None):
        """Inject a system call into the child process.

        This function is blocking by default. When the callback parameter is
        given, this function becomes non-blocking, and the return value will
        _not_ be the result from the system call. (Instead you can find the
        return value by inspecting the Event structure, which is passed onto
        the callback function as the first parameter.)

        """
        # convert system call name to number
        if isinstance(syscall_number, str):
            syscall_number = _tracy.get_syscall_number(syscall_number)

        # convert tuple/list of arguments to SyscallArguments object
        if isinstance(args, (list, tuple)):
            obj = copy.copy(self.child.event.args)
            for x in xrange(len(args)):
                setattr(obj, 'a%d' % x, args[x])
            args = obj

        if callback is None:
            ret = c_long()
            _tracy.tracy_inject_syscall(self.child,
                                        syscall_number,
                                        args,
                                        byref(ret))
            return ret.value
        else:
            self.gc = _hook_func(callback)
            return _tracy.tracy_inject_syscall_async(self.child,
                                                     syscall_number,
                                                     args,
                                                     self.gc)


class Tracy:
    # a global dictionary of all Tracy objects, with key is _Tracy's address
    tracies = {}

    def __init__(self, options=0):
        """Initialize a new Tracy instance."""
        tracy = _tracy.tracy_init(options)
        self.tracy = tracy.contents

        # dictionary with function addresses for each syscall number
        self.hooks = {}

        # a list to keep garbage collectable stuff in-memory
        self.gc = [_tracy]

        # add this Tracy object to the list of tracies
        self.tracies[cast(tracy, c_void_p).value] = self

    def __del__(self):
        """Release a Tracy instance."""
        _tracy.tracy_free(self.tracy)

    @staticmethod
    def from_event(event):
        ptr = cast(event.child.contents.tracy, c_void_p).value
        return Tracy.tracies[ptr]

    def execute(self, *argv):
        """Execute a new child."""
        # go through some ctypes horror to pass a list of strings
        args = (c_char_p * (len(argv) + 1))()
        args[:] = list(argv) + [None]
        child = _tracy.tracy_exec(self.tracy, args)
        return Child(self.tracy, child)

    def attach(self, pid):
        """Attach to an existing process."""
        child = _tracy.tracy_attach(self.tracy, pid)
        return Child(self.tracy, child)

    def main(self):
        """Enter a simple tracy-event loop."""
        _tracy.tracy_main(self.tracy)

    def hook(self, name, func):
        """Set a hook handler for the given system call."""
        # set function for this syscall number
        self.hooks[_tracy.get_syscall_number(name)] = func

        def _func(e):
            # obtain the function through the syscall number
            fn = Tracy.from_event(e.contents).hooks[e.contents.args.syscall]
            ret = fn(e.contents,
                     e.contents.args,
                     e.contents.child.contents.pre_syscall)
            return ret if ret is not None else HOOK_CONTINUE

        # we have to retain the _hook_func object in order to keep it from
        # being garbage collected
        self.gc.append(_hook_func(_func))
        _tracy.tracy_set_hook(self.tracy, name, self.gc[-1])

    def signal_hook(self, func):
        """Set a signal hook, which is called for each signal."""
        self.sighookcb = func

        def _func(e):
            fn = Tracy.from_event(e.contents).sighookcb
            ret = fn(e.contents,
                     e.contents.args,
                     e.contents.child.contents.pre_syscall)
            return ret if ret is not None else HOOK_CONTINUE

        self.gc.append(_hook_func(_func))
        _tracy.tracy_set_signal_hook(self, self.gc[-1])

    def default_hook(self, func):
        """Set the default hook."""
        self.defhookcb = func

        def _func(e):
            fn = Tracy.from_event(e.contents).defhookcb
            ret = fn(e.contents,
                     e.contents.args,
                     e.contents.child.contents.pre_syscall)
            return ret if ret is not None else HOOK_CONTINUE

        self.gc.append(_hook_func(_func))
        _tracy.tracy_set_default_hook(self.tracy, self.gc[-1])
