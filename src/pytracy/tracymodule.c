#include <Python.h>
#include <structmember.h>
#include "tracy.h"

// types copied from PyMemberDef
typedef struct _pyobj_ptr_t {
    int type;
    Py_ssize_t offset;
} pyobj_ptr_t;

// gets the value at the offset of the first pointer, e.g. if the PyObject
// looks like the following: struct { PyObject_HEAD void *ptr }; then this
// function will get the object at the offset of the value at the pointer..
// note that closure is a pyobj_ptr_t object, which provides us the object
// type and offset
PyObject *pyobj_ptr_get(PyObject *obj, void *closure)
{
    pyobj_ptr_t *obj_info = (pyobj_ptr_t *) closure;

    // follow the pointer after the PyObject_HEAD header and add the correct
    // offset to it
    unsigned char *ptr = *(unsigned char **)(obj + 1) + obj_info->offset;

    switch (obj_info->type) {
        case T_LONG: return PyLong_FromLong(*(long *)(ptr));
        default: return NULL;
    }
}

// sets a value, just like pyobj_ptr_get
int pyobj_ptr_set(PyObject *obj, PyObject *value, void *closure)
{
    pyobj_ptr_t *obj_info = (pyobj_ptr_t *) closure;

    // follow the pointer after the PyObject_HEAD header and add the correct
    // offset to it
    unsigned char *ptr = *(unsigned char **)(obj + 1) + obj_info->offset;

    switch (obj_info->type) {
        case T_LONG: *(long *) ptr = PyLong_AsLong(value); return 0;
        default: return -1;
    }
}

//
// Tracy System Call Arguments Object
//

typedef struct {
    PyObject_HEAD
    struct tracy_sc_args *args;
} tracy_sc_args_object;

static pyobj_ptr_t sc_args_ptr_info[] = {
    {T_LONG, offsetof(struct tracy_sc_args, a0)},
    {T_LONG, offsetof(struct tracy_sc_args, a1)},
    {T_LONG, offsetof(struct tracy_sc_args, a2)},
    {T_LONG, offsetof(struct tracy_sc_args, a3)},
    {T_LONG, offsetof(struct tracy_sc_args, a4)},
    {T_LONG, offsetof(struct tracy_sc_args, a5)},
    {T_LONG, offsetof(struct tracy_sc_args, a5)},
    {T_LONG, offsetof(struct tracy_sc_args, return_code)},
    {T_LONG, offsetof(struct tracy_sc_args, syscall)},
    {T_LONG, offsetof(struct tracy_sc_args, ip)},
    {T_LONG, offsetof(struct tracy_sc_args, sp)},
};

static PyGetSetDef tracy_sc_args_getset[] = {
    {"a0", &pyobj_ptr_get, &pyobj_ptr_set, "first argument",
        &sc_args_ptr_info[0]},
    {"a1", &pyobj_ptr_get, &pyobj_ptr_set, "second argument",
        &sc_args_ptr_info[1]},
    {"a2", &pyobj_ptr_get, &pyobj_ptr_set, "third argument",
        &sc_args_ptr_info[2]},
    {"a3", &pyobj_ptr_get, &pyobj_ptr_set, "fourth argument",
        &sc_args_ptr_info[3]},
    {"a4", &pyobj_ptr_get, &pyobj_ptr_set, "fifth argument",
        &sc_args_ptr_info[4]},
    {"a5", &pyobj_ptr_get, &pyobj_ptr_set, "sixth argument",
        &sc_args_ptr_info[5]},
    {"retcode", &pyobj_ptr_get, &pyobj_ptr_set, "return value",
        &sc_args_ptr_info[6]},
    {"syscall", &pyobj_ptr_get, &pyobj_ptr_set, "system call number",
        &sc_args_ptr_info[7]},
    {"ip", &pyobj_ptr_get, &pyobj_ptr_set, "instruction pointer",
        &sc_args_ptr_info[8]},
    {"sp", &pyobj_ptr_get, &pyobj_ptr_set, "stack pointer",
        &sc_args_ptr_info[9]},
    {NULL},
};

static int tracy_sc_args_init(tracy_sc_args_object *self, PyObject *args,
    PyObject *kwargs)
{
    static char *kwlist[] = {"a0", "a1", "a2", "a3", "a4", "a5", "retcode",
        "syscall", "ip", "sp", NULL};

    // TODO this is very bad.. either we have a memleak (current situation)
    // or we don't know whether to free() it in the destructor. probably the
    // best fix will be having a `struct tracy_sc_args' object as well.
    self->args = (struct tracy_sc_args *) calloc(1,
        sizeof(struct tracy_sc_args));
    if(self->args == NULL) {
        return -1;
    }

    if(!PyArg_ParseTupleAndKeywords(args, kwargs, "|llllllllll", kwlist,
            &self->args->a0, &self->args->a1, &self->args->a2,
            &self->args->a3, &self->args->a4, &self->args->a5,
            &self->args->return_code, &self->args->syscall, &self->args->ip,
            &self->args->sp)) {
        return -1;
    }
    return 0;
}

PyObject *tracy_sc_args_repr(tracy_sc_args_object *self)
{
    static char *kwlist[] = {"a0", "a1", "a2", "a3", "a4", "a5", "retcode",
        "syscall", "ip", "sp", NULL};

    PyObject *str = PyString_FromString("tracy.SyscallArguments(");

    int first = 1;

    // bit hacky, but gives the cleanest output
    for (int i = 0; i < sizeof(struct tracy_sc_args) / sizeof(long); i++) {
        long value = ((long *) self->args)[i];
        if(value != 0) {
            if(first) first = 0;
            else PyString_ConcatAndDel(&str, PyString_FromString(", "));

            // this cannot be done with a ternary statement, because gcc
            // will whine about long integer vs pointer format strings
            if(value < 0 && value > -0x1000) {
                PyString_ConcatAndDel(&str, PyString_FromFormat("%s=%ld",
                    kwlist[i], value));
            }
            else {
                PyString_ConcatAndDel(&str, PyString_FromFormat("%s=%p",
                    kwlist[i], (void *) value));
            }
        }
    }

    PyString_ConcatAndDel(&str, PyString_FromString(")"));
    return str;
}

static PyTypeObject tracy_sc_args_type = {
    PyObject_HEAD_INIT(NULL)
    .tp_name = "tracy.SyscallArguments",
    .tp_basicsize = sizeof(tracy_sc_args_object),
    .tp_flags = Py_TPFLAGS_DEFAULT,
    .tp_doc = "Tracy System Call Argument(s) Object",
    .tp_new = PyType_GenericNew,
    .tp_getset = tracy_sc_args_getset,
    .tp_init = (initproc) &tracy_sc_args_init,
    .tp_repr = (reprfunc) &tracy_sc_args_repr,
};

//
// Tracy Event Object
//

// forward declaration of &tracy_child_type
static PyTypeObject *tracy_child_type_ptr = NULL;

typedef struct {
    PyObject_HEAD
    struct tracy_event *event;

    // python objects of child and args in the event object
    PyObject *child;
    PyObject *args;
} tracy_event_object;

static int tracy_event_init(tracy_event_object *self, PyObject *args,
    PyObject *kwargs)
{
    static char *kwlist[] = {"typ", "child", "syscall_num", "signal_num",
        "args", NULL};

    // TODO this is very bad.. either we have a memleak (current situation)
    // or we don't know whether to free() it in the destructor. probably the
    // best fix will be having a `struct tracy_event' object as well.
    self->event = (struct tracy_event *) calloc(1,
        sizeof(struct tracy_event));
    if(self->event == NULL) {
        return -1;
    }

    if(!PyArg_ParseTupleAndKeywords(args, kwargs, "iO!llO!", kwlist,
            &self->event->type, tracy_child_type_ptr, &self->child,
            &self->event->syscall_num, &self->event->signal_num,
            &tracy_sc_args_type, &self->args)) {
        return -1;
    }

    // copy the child and args into the event object
    //self->event.child = ((tracy_child_object *) self->child)->child;
    //memcpy(&self->event.args, ((tracy_sc_args_object *) self->args)->args,
    //    sizeof(struct tracy_sc_args));
    return 0;
}

static PyObject *tracy_event_getchild(tracy_event_object *self, void *closure)
{
    Py_INCREF(self->child);
    return self->child;
}

static PyObject *tracy_event_getargs(tracy_event_object *self, void *closure)
{
    Py_INCREF(self->args);
    return self->args;
}

static PyGetSetDef tracy_event_getset[] = {
    {"child", (getter) tracy_event_getchild, NULL, "child process", NULL},
    {"args", (getter) tracy_event_getargs, NULL, "system call arguments",
        NULL},
    {NULL},
};

static void tracy_event_free(tracy_event_object *self)
{
    // `child' is a weak reference

    // free the sc args
    Py_DECREF(self->args);
}

static PyTypeObject tracy_event_type = {
    PyObject_HEAD_INIT(NULL)
    .tp_name = "tracy.Event",
    .tp_basicsize = sizeof(tracy_event_object),
    .tp_flags = Py_TPFLAGS_DEFAULT,
    .tp_doc = "Tracy Event Object",
    .tp_new = PyType_GenericNew,
    .tp_getset = tracy_event_getset,
    .tp_init = (initproc) &tracy_event_init,
    .tp_dealloc = (destructor) &tracy_event_free,
};

//
// Tracy Child Object
//

typedef struct {
    PyObject_HEAD
    struct tracy_child *child;
    PyObject *event;
} tracy_child_object;

PyObject *tracy_child_read_mem(tracy_child_object *self, PyObject *args)
{
    void *addr; long  size;

    // TODO ability to pass an already allocated buffer

    if(!PyArg_ParseTuple(args, "ll", &addr, &size)) {
        printf("incorrect args..\n");
        Py_INCREF(Py_None);
        return Py_None;
    }

    // although I'm confident that this is ugly.. python strings are
    // immutable, so we *have* to do this.

    void *mem = malloc(size);
    if(mem == NULL) {
        // TODO set error
        return NULL;
    }

    ssize_t ret = tracy_read_mem(self->child, mem, addr, size);
    if(ret != size) {
        // TODO set error
        free(mem);
        return NULL;
    }

    PyObject *str = PyString_FromStringAndSize((const char *) mem, size);
    if(str == NULL) {
        // TODO set error
        free(mem);
        return NULL;
    }

    free(mem);
    return str;
}

PyObject *tracy_child_write_mem(tracy_child_object *self, PyObject *args)
{
    char *mem; int len; void *addr;

    if(!PyArg_ParseTuple(args, "ls#", &addr, &mem, &len)) {
        return NULL;
    }

    ssize_t ret = tracy_write_mem(self->child, addr, mem, len);
    if(ret != len) {
        Py_INCREF(Py_False);
        return Py_False;
    }

    Py_INCREF(Py_True);
    return Py_True;
}

PyObject *tracy_child_inject(tracy_child_object *self, PyObject *args,
    PyObject *kwargs)
{
    static char *kwlist[] = {"syscall_number", "args", "cb", NULL};

    long syscall_number; tracy_sc_args_object *sc_args; PyObject *cb = NULL;

    if(!PyArg_ParseTupleAndKeywords(args, kwargs, "lO!|O", kwlist,
            &syscall_number, &tracy_sc_args_type, &sc_args, &cb)) {
        return NULL;
    }

    // if callback is set, it must be a callable
    if(cb != NULL && PyCallable_Check(cb) == 0) {
        // TODO add error message
        return NULL;
    }

    // if callback is not set, then the call is blocking.
    if(cb == NULL) {
        long ret;
        int success = tracy_inject_syscall(self->child, syscall_number,
            sc_args->args, &ret);
        if(success < 0) {
            Py_INCREF(Py_False);
            return Py_False;
        }
        return PyLong_FromLong(ret);
    }

    // this injected system call is non-blocking (not yet implemented!)
    return NULL;
}

PyObject *tracy_child_deny(tracy_child_object *self)
{
    tracy_deny_syscall(self->child);
    Py_INCREF(Py_None);
    return Py_None;
}

static PyMethodDef tracy_child_methods[] = {
    {"read", (PyCFunction) &tracy_child_read_mem, METH_VARARGS,
        "read process memory of this child"},
    {"write", (PyCFunction) &tracy_child_write_mem, METH_VARARGS,
        "write process memory to this child"},
    {"inject", (PyCFunction) &tracy_child_inject, METH_KEYWORDS,
        "inject a system call"},
    {"deny", (PyCFunction) &tracy_child_deny, METH_NOARGS,
        "deny a system call"},
    {NULL},
};

static PyMemberDef tracy_child_members[] = {
    {"event", T_OBJECT_EX, offsetof(tracy_child_object, event), 0,
        "tracy.Event object which belongs to this child"},
    {NULL},
};

static PyObject *tracy_child_getpre(tracy_child_object *self, void *closure)
{
    return PyBool_FromLong(self->child->pre_syscall);
}

static PyObject *tracy_child_getpost(tracy_child_object *self, void *closure)
{
    return PyBool_FromLong(self->child->pre_syscall == 0);
}

static PyGetSetDef tracy_child_getset[] = {
    {"pre", (getter) &tracy_child_getpre, NULL,
        "true if this call is pre syscall", NULL},
    {"post", (getter) &tracy_child_getpost, NULL,
        "true if this call is post syscall", NULL},
    {NULL},
};

static void tracy_child_free(tracy_child_object *self)
{
    // free the event
    Py_DECREF(self->event);
}

static PyTypeObject tracy_child_type = {
    PyObject_HEAD_INIT(NULL)
    .tp_name = "tracy.Child",
    .tp_basicsize = sizeof(tracy_child_object),
    .tp_flags = Py_TPFLAGS_DEFAULT,
    .tp_doc = "Tracy Child Process Object",
    .tp_new = PyType_GenericNew,
    .tp_members = tracy_child_members,
    .tp_dealloc = (destructor) &tracy_child_free,
    .tp_methods = tracy_child_methods,
    .tp_getset = tracy_child_getset,
};

// returns the PyObject according with this tracy_child, if it has already
// been allocated, then it returns the existing object
PyObject *tracy_child_pyobj(struct tracy_child *child)
{
    // initialize the tracy.Child object
    if(child->custom2 == NULL) {
        PyObject *ret = _PyObject_New(&tracy_child_type);
        // TODO check for NULL
        ((tracy_child_object *) ret)->child = child;
        child->custom2 = ret;
    }

    // initialize the tracy.Event object
    if(child->event.custom == NULL) {
        tracy_event_object *event = (tracy_event_object *)
            _PyObject_New(&tracy_event_type);

        // TODO check for NULL
        child->event.custom = event;

        ((tracy_child_object *) child->custom2)->event = (PyObject *) event;

        // event->child points to the tracy.Child object
        event->child = child->custom2;

        // event->event points to the tracy_event object
        event->event = &child->event;

        // initialize the tracy.SyscallArguments object (in the tracy.Event
        // object)

        tracy_sc_args_object *args = (tracy_sc_args_object *)
            _PyObject_New(&tracy_sc_args_type);

        // TODO check for NULL
        event->args = (PyObject *) args;
        args->args = &child->event.args;
    }

    // return the PyObject pointing to the tracy.Child object
    return (PyObject *) child->custom2;
}

//
// Tracy Object
//

typedef struct {
    PyObject_HEAD
    struct tracy *tracy;
} tracy_object;

static int _tracy_init(tracy_object *self, PyObject *args, PyObject *kwargs)
{
    static char *kwlist[] = {"opt", NULL};
    long opt = 0;

    if(!PyArg_ParseTupleAndKeywords(args, kwargs, "|l", kwlist, &opt)) {
        return -1;
    }

    self->tracy = tracy_init(opt);
    if(self->tracy == NULL) {
        // TODO correct error message
        return -1;
    }

    return 0;
}

static void _tracy_free(tracy_object *self)
{
    // first we free all the tracy.Child objects (because tracy_free
    // frees everything related to this tracy object)
    for (struct soxy_ll_item *p = self->tracy->childs->head; p != NULL;
            p = p->next) {
        PyObject *child = tracy_child_pyobj(
            (struct tracy_child *) p->data);
        Py_DECREF(child);
    }

    tracy_free(self->tracy);
}

static PyObject *_tracy_loop(tracy_object *self)
{
    tracy_main(self->tracy);

    Py_INCREF(Py_None);
    return Py_None;
}

static PyObject *_tracy_attach(tracy_object *self, PyObject *args)
{
    pid_t pid;

    if(!PyArg_ParseTuple(args, "l", &pid)) {
        Py_INCREF(Py_None);
        return Py_None;
    }

    struct tracy_child *child = tracy_attach(self->tracy, pid);
    if(child == NULL) {
        Py_INCREF(Py_None);
        return Py_None;
    }

    return tracy_child_pyobj(child);
}

static PyObject *_tracy_execv(tracy_object *self, PyObject *args)
{
    char **argv = (char **) malloc(sizeof(char *) * (PyTuple_Size(args) + 1));
    if(argv == NULL) {
        // TODO return out of memory error
        Py_INCREF(Py_None);
        return Py_None;
    }

    for (long i = 0; i < PyTuple_Size(args); i++) {
        PyObject *arg = PyTuple_GetItem(args, i);
        argv[i] = PyString_AsString(arg);
    }

    argv[PyTuple_Size(args)] = NULL;
    struct tracy_child *child = fork_trace_exec(self->tracy,
        PyTuple_Size(args), argv);

    free(argv);

    if(child == NULL) {
        Py_INCREF(Py_None);
        return Py_None;
    }

    return tracy_child_pyobj(child);
}

static PyObject *_tracy_children(tracy_object *self)
{
    PyObject *ret = PyList_New(0);

    if(self->tracy->childs == NULL) {
        return ret;
    }

    for (struct soxy_ll_item *p = self->tracy->childs->head; p != NULL;
            p = p->next) {
        PyList_Append(ret, tracy_child_pyobj(p->data));
    }

    return ret;
}

static PyObject *_tracy_main(tracy_object *self)
{
    return PyLong_FromLong(tracy_main(self->tracy));
}

int _tracy_hook_callback(struct tracy_event *event, void *data)
{
    // `event->custom' points to the tracy.Event of this `event'
    tracy_event_object *e = (tracy_event_object *) event->custom;

    // `data' points to a Callable PyObject
    // `e->child' points to tracy.Child and finally
    // `e->args' points to tracy.SyscallArguments
    PyObject *ret = PyObject_CallFunctionObjArgs(
        (PyObject *) data, e->child, e, e->args, NULL);

    // return int as value..
    return ret == Py_None ? TRACY_HOOK_CONTINUE : (int) PyLong_AsLong(ret);
}

static PyObject *_tracy_hook(tracy_object *self, PyObject *args)
{
    char *funcname; PyObject *callable;

    if(!PyArg_ParseTuple(args, "s|O", &funcname, &callable)) {
        Py_INCREF(Py_None);
        return Py_None;
    }

    if(callable != Py_None && !PyCallable_Check(callable)) {
        // TODO throw exception
        return NULL;
    }

    Py_INCREF(callable);
    tracy_set_hook(self->tracy, funcname, &_tracy_hook_callback, callable);

    Py_INCREF(Py_None);
    return Py_None;
}

static PyMethodDef tracy_methods[] = {
    {"loop", (PyCFunction) &_tracy_loop, METH_NOARGS, "see tracy_main"},
    {"attach", (PyCFunction) &_tracy_attach, METH_VARARGS,
        "attach to a process"},
    {"execv", (PyCFunction) &_tracy_execv, METH_VARARGS,
        "exec(2) a new process"},
    {"children", (PyCFunction) &_tracy_children, METH_NOARGS,
        "children of this tracy object"},
    {"loop", (PyCFunction) &_tracy_main, METH_NOARGS,
        "main loop of this tracy object"},
    {"hook", (PyCFunction) &_tracy_hook, METH_VARARGS,
        "set, replace or remove a hook function"},
    {NULL},
};

static PyObject *_tracy_getfpid(tracy_object *self, void *closure)
{
    return PyLong_FromLong(self->tracy->fpid);
}

static PyObject *_tracy_getopt(tracy_object *self, void *closure)
{
    return PyLong_FromLong(self->tracy->opt);
}

static PyGetSetDef tracy_getset[] = {
    {"fpid", (getter) _tracy_getfpid, NULL, "foreground pid", NULL},
    {"opt", (getter) _tracy_getopt, NULL, "tracy flags", NULL},
    // TODO defhook, special events
    {NULL},
};

static PyTypeObject tracy_type = {
    PyObject_HEAD_INIT(NULL)
    .tp_name = "tracy.Tracy",
    .tp_basicsize = sizeof(tracy_object),
    .tp_flags = Py_TPFLAGS_DEFAULT,
    .tp_doc = "Tracy Object",
    .tp_new = PyType_GenericNew,
    .tp_init = (initproc) &_tracy_init,
    .tp_dealloc = (destructor) &_tracy_free,
    .tp_methods = tracy_methods,
    .tp_getset = tracy_getset,
};

//
// Module Methods
//

static PyMethodDef module_methods[] = {
    {NULL},
};

PyMODINIT_FUNC inittracy(void)
{
    PyObject *m = Py_InitModule("tracy", module_methods);
    if(m == NULL) return;

    if(PyType_Ready(&tracy_type) < 0 ||
            PyType_Ready(&tracy_sc_args_type) < 0 ||
            PyType_Ready(&tracy_child_type) < 0 ||
            PyType_Ready(&tracy_event_type) < 0) {
        return;
    }

    tracy_child_type_ptr = &tracy_child_type;

    //
    // Initialize all Tracy Global Values
    //

#define INT_CONSTANT(x) PyModule_AddIntConstant(m, #x, TRACY_##x)

    INT_CONSTANT(TRACE_CHILDREN);
    INT_CONSTANT(VERBOSE);

    INT_CONSTANT(MEMORY_FALLBACK);
    INT_CONSTANT(USE_SAFE_TRACE);

    INT_CONSTANT(EVENT_NONE);
    INT_CONSTANT(EVENT_SYSCALL);
    INT_CONSTANT(EVENT_SIGNAL);
    INT_CONSTANT(EVENT_INTERNAL);
    INT_CONSTANT(EVENT_QUIT);

    INT_CONSTANT(HOOK_CONTINUE);
    INT_CONSTANT(HOOK_KILL_CHILD);
    INT_CONSTANT(HOOK_ABORT);
    INT_CONSTANT(HOOK_NOHOOK);

    //
    // Initialize all Tracy classes
    //

    Py_INCREF(&tracy_type);
    PyModule_AddObject(m, "Tracy", (PyObject *) &tracy_type);

    Py_INCREF(&tracy_child_type);
    PyModule_AddObject(m, "Child", (PyObject *) &tracy_child_type);

    Py_INCREF(&tracy_sc_args_type);
    PyModule_AddObject(m, "SyscallArguments",
        (PyObject *) &tracy_sc_args_type);

    Py_INCREF(&tracy_event_type);
    PyModule_AddObject(m, "Event", (PyObject *) &tracy_event_type);
}
