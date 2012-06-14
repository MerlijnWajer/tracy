#include <Python.h>

typedef struct {
    PyObject_HEAD
    struct tracy *obj;
} tracy_TracyObject;

static PyTypeObject tracy_TracyType = {
    PyObject_HEAD_INIT(NULL)
    0,
    "tracy.Tracy",
    sizeof(tracy_TracyObject),
    .tp_flags = Py_TPFLAGS_DEFAULT,
    .tp_doc = "Tracy Object",
    .tp_new = PyType_GenericNew,
};

static PyMethodDef tracy_methods[] = {
    {NULL},
};

PyMODINIT_FUNC void inittracy(void)
{
    PyObject *m = Py_InitModule("tracy", tracy_methods);
    if(m == NULL) return;

    if(PyType_Ready(&tracy_TracyType) < 0) {
        return;
    }

    Py_INCREF(&tracy_TracyObject);
    PyModule_AddObject(m, "Tracy", (PyObject *) &tracy_TracyType);
}
