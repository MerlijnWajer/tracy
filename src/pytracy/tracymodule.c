#include <Python.h>
#include <structmember.h>
#include "tracy.h"

typedef struct {
    PyObject_HEAD
    struct tracy_sc_args sc;
} tracy_sc_args_object;

static PyMemberDef tracy_sc_args_members[] = {
    {"a0", T_LONG, offsetof(tracy_sc_args_object, sc.a0), 0,
        "first argument"},
    {"a1", T_LONG, offsetof(tracy_sc_args_object, sc.a1), 0,
        "second argument"},
    {"a2", T_LONG, offsetof(tracy_sc_args_object, sc.a2), 0,
        "third argument"},
    {"a3", T_LONG, offsetof(tracy_sc_args_object, sc.a3), 0,
        "fourth argument"},
    {"a4", T_LONG, offsetof(tracy_sc_args_object, sc.a4), 0,
        "fifth argument"},
    {"a5", T_LONG, offsetof(tracy_sc_args_object, sc.a5), 0,
        "sixth argument"},
    {"retcode", T_LONG, offsetof(tracy_sc_args_object, sc.return_code), 0,
        "return value"},
    {"syscall", T_LONG, offsetof(tracy_sc_args_object, sc.syscall), 0,
        "syscall number"},
    {"ip", T_LONG, offsetof(tracy_sc_args_object, sc.ip), 0,
        "instruction pointer"},
    {"sp", T_LONG, offsetof(tracy_sc_args_object, sc.sp), 0, "stack pointer"},
    {NULL},
};

static int tracy_sc_args_init(tracy_sc_args_object *self, PyObject *args,
    PyObject *kwargs)
{
    static char *kwlist[] = {"a0", "a1", "a2", "a3", "a4", "a5", "retcode",
        "syscall", "ip", "sp", NULL};

    if(!PyArg_ParseTupleAndKeywords(args, kwargs, "|llllllllll", kwlist,
            &self->sc.a0, &self->sc.a1, &self->sc.a2, &self->sc.a3,
            &self->sc.a4, &self->sc.a5, &self->sc.return_code,
            &self->sc.syscall, &self->sc.ip, &self->sc.sp)) {
        return -1;
    }
    return 0;
}

static PyTypeObject tracy_sc_args_type = {
    PyObject_HEAD_INIT(NULL)
    .tp_name = "tracy.SyscallArguments",
    .tp_basicsize = sizeof(tracy_sc_args_object),
    .tp_flags = Py_TPFLAGS_DEFAULT,
    .tp_doc = "Tracy System Call Argument(s) Object",
    .tp_new = PyType_GenericNew,
    .tp_members = tracy_sc_args_members,
    .tp_init = (initproc) &tracy_sc_args_init,
};

typedef struct {
    PyObject_HEAD
    struct tracy_child child;
} tracy_child_object;

static PyTypeObject tracy_child_type = {
    PyObject_HEAD_INIT(NULL)
    .tp_name = "tracy.Child",
    .tp_basicsize = sizeof(tracy_child_object),
    .tp_flags = Py_TPFLAGS_DEFAULT,
    .tp_doc = "Tracy Child Process Object",
    .tp_new = PyType_GenericNew,
};

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

    //self->tracy = tracy_init(opt);
    return 0;
}

static void _tracy_free(tracy_object *self)
{
    if(self->tracy != NULL) {
        //tracy_free(self->tracy);
        self->tracy = NULL;
    }
}

static PyObject *_tracy_loop(tracy_object *self)
{
    //tracy_main(self->tracy);

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

    //struct tracy_child *child = tracy_attach(self->tracy, pid);
    //if(child == NULL) {
        // ...
    //}

    // create tracy_child_object instance
    // ...

    Py_INCREF(Py_None);
    return Py_None;
}

static PyObject *_tracy_execv(tracy_object *self, PyObject *args)
{
    char **argv = (char **) malloc(sizeof(char *) * PyTuple_Size(args));
    for (long i = 0; i < PyTuple_Size(args); i++) {
        PyObject *arg = PyTuple_GetItem(args, i);
        argv[i] = PyString_AsString(arg);
    }

    //struct tracy_child *child = fork_trace_exec(self->tracy,
        //PyTuple_Size(args), argv);

    free(argv);

    // create tracy_child_object instance
    // ...

    Py_INCREF(Py_None);
    return Py_None;
}

static PyMethodDef tracy_methods[] = {
    {"loop", (PyCFunction) &_tracy_loop, METH_NOARGS, "see tracy_main"},
    {"attach", (PyCFunction) &_tracy_attach, METH_VARARGS,
        "attach to a process"},
    {"execv", (PyCFunction) &_tracy_execv, METH_VARARGS,
        "exec(2) a new process"},
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
};

static PyMethodDef module_methods[] = {
    {NULL},
};

PyMODINIT_FUNC inittracy(void)
{
    PyObject *m = Py_InitModule("tracy", module_methods);
    if(m == NULL) return;

    if(PyType_Ready(&tracy_type) < 0 ||
            PyType_Ready(&tracy_sc_args_type) < 0 ||
            PyType_Ready(&tracy_child_type) < 0) {
        return;
    }

    Py_INCREF(&tracy_type);
    PyModule_AddObject(m, "Tracy", (PyObject *) &tracy_type);

    Py_INCREF(&tracy_child_type);
    PyModule_AddObject(m, "Child", (PyObject *) &tracy_child_type);

    Py_INCREF(&tracy_sc_args_type);
    PyModule_AddObject(m, "SyscallArguments",
        (PyObject *) &tracy_sc_args_type);
}
