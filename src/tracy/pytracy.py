"""Python bindings for Tracy."""
from ctypes import Structure, cdll, POINTER
from ctypes import c_long, c_int, c_void_p, c_byte, c_char_p
import sys


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
    _fields_ = [
        ('typ', c_int),
        ('child', c_void_p),
        ('syscall_num', c_long),
        ('signal_num', c_long),
        ('siginfo', siginfo_t),
    ]


class SpecialEvents(Structure):
    _fields_ = [
        # TODO callback stuff
        ('child_create', c_void_p),
    ]


class _Tracy(Structure):
    _fields_ = [
        ('childs', c_void_p),
        ('hooks', c_void_p),
        ('fpid', c_long),
        ('opt', c_long),
        # TODO callback stuff
        ('defhook', c_void_p),
        ('signal_hook', c_void_p),
        ('se', SpecialEvents),
    ]


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
    _fields_ = [
        ('pid', c_long),
        ('attached', c_int),
        ('pre_syscall', c_int),
        ('mem_fd', c_int),
        ('mem_fallback', c_int),
        ('denied_nr', c_int),
        ('suppress', c_int),
        ('custom', c_void_p),
        ('tracy', c_void_p),
        ('inj', InjectData),
        ('frozen_by_fork', c_int),
        ('received_first_sigstop', c_int),
        ('orig_pc', c_long),
        ('orig_trampy_pid_reg', c_long),
        ('orig_return_code', c_long),
        ('event', Event),
    ]


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


def _set_func(name, restype, *argtypes):
    getattr(_tracy, name).restype = restype
    getattr(_tracy, name).argtypes = argtypes

# TODO improve path support
_tracy = cdll.LoadLibrary('./libtracy.so')
_set_func('tracy_init', POINTER(_Tracy), c_long)
_set_func('tracy_free', c_int, POINTER(_Tracy))
_set_func('tracy_quit', c_int, POINTER(_Tracy), c_int)
_set_func('tracy_main', c_int, POINTER(_Tracy))
_set_func('tracy_exec', POINTER(_Child), POINTER(_Tracy), c_void_p)
_set_func('tracy_attach', POINTER(_Child), POINTER(_Tracy), c_long)
_set_func('tracy_add_child', POINTER(_Child), POINTER(_Tracy), c_long)
_set_func('tracy_wait_event', POINTER(Event), POINTER(_Tracy), c_long)
_set_func('tracy_continue', c_int, POINTER(Event), c_int)
_set_func('tracy_kill_child', c_int, POINTER(_Child))
_set_func('tracy_remove_child', c_int, POINTER(_Child))
_set_func('tracy_children_count', c_int, POINTER(_Tracy))
_set_func('get_syscall_name', c_char_p, c_int)
_set_func('get_signal_name', c_char_p, c_int)
# TODO implement callback stuff
_set_func('tracy_set_hook', c_int, POINTER(_Tracy), c_char_p, c_void_p)
_set_func('tracy_set_signal_hook', c_int, POINTER(_Tracy), c_void_p)
_set_func('tracy_set_default_hook', c_int, POINTER(_Tracy), c_void_p)
_set_func('tracy_execute_hook',
          c_int,
          POINTER(_Tracy),
          c_char_p,
          POINTER(Event))


class Child:
    def __init__(self, tracy, child):
        """Initialize a new Tracy Child."""
        self.tracy = tracy
        self.child = child


class Tracy:
    def __init__(self, options=0):
        """Initialize a new Tracy instance."""
        self.tracy = _tracy.tracy_init(options).contents

    def __del__(self):
        """Release a Tracy instance."""
        # when the GC is doing its stuff at the end of a script, it might
        # already have free'd _tracy..
        if _tracy is not None:
            _tracy.tracy_free(self.tracy)

    def execute(self, *argv):
        """Execute a new child."""
        # go through some ctypes horror to pass a list of strings
        args = (c_char_p * (len(argv) + 1))()
        args[:] = list(argv) + [None]
        child = _tracy.tracy_exec(self.tracy, args).contents
        return Child(self.tracy, child)

    def attach(self, pid):
        """Attach to an existing process."""
        child = _tracy.tracy_attach(self.tracy, pid).contents
        return Child(self.tracy, child)

    def main(self):
        """Enter a simple tracy-event loop."""
        _tracy.tracy_main(self.tracy)
