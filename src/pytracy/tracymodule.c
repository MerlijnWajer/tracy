#include <Python.h>

typedef struct {
    PyObject_HEAD
    struct tracy *tracy;
} TracyObject;

static PyTypeObject TracyType = {
    PyObject_HEAD_INIT(NULL)
    0,
    "tracy.Tracy",
    sizeof(TracyObject),
    .tp_flags = Py_TPFLAGS_DEFAULT,
    .tp_doc = "Tracy Object",
    .tp_new = PyType_GenericNew,
};

static PyMethodDef tracy_methods[] = {
    {NULL},
};

PyMODINIT_FUNC inittracy(void)
{
    PyObject *m = Py_InitModule("tracy", tracy_methods);
    if(m == NULL) return;

    if(PyType_Ready(&TracyType) < 0) {
        return;
    }

    Py_INCREF(&TracyType);
    PyModule_AddObject(m, "Tracy", (PyObject *) &TracyType);
}
