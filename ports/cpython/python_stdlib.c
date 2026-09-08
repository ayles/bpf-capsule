// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
// A sys.meta_path loader for the unmodified Python sources in CPython's Lib/.
// The host stages one packed, read-only image in Capsule memory; imports then
// compile and execute those sources through CPython's ordinary machinery.
#include "python_stdlib.h"

#include <Python.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <string.h>

#define CAPSULE_STDLIB_PACKAGE 1u

// This embedding exposes modules, not filesystem paths. Optional startup
// files (such as pyvenv.cfg) are absent; creating files is unsupported.
// Keep this policy local rather than changing Capsule's generic OS stubs.
int open(const char* path, int flags, ...) {
    (void)path;
    errno = flags & (O_WRONLY | O_RDWR | O_CREAT | O_TRUNC) ? EROFS : ENOENT;
    return -1;
}

struct capsule_stdlib_header {
    char magic[8];
    uint32_t version;
    uint32_t count;
    uint32_t names_size;
    uint32_t sources_size;
};

struct capsule_stdlib_entry {
    uint32_t name_offset;
    uint32_t source_offset;
    uint32_t source_size;
    uint32_t flags;
};

static const unsigned char* stdlib_image;
static const struct capsule_stdlib_header* stdlib_header;
static const struct capsule_stdlib_entry* stdlib_entries;
static const char* stdlib_names;

static const struct capsule_stdlib_entry* stdlib_find(const char* name) {
    uint32_t first = 0;
    uint32_t last = stdlib_header->count;
    while (first < last) {
        uint32_t middle = first + (last - first) / 2;
        const struct capsule_stdlib_entry* entry = &stdlib_entries[middle];
        int order = strcmp(name, stdlib_names + entry->name_offset);
        if (order < 0) {
            last = middle;
        } else if (order > 0) {
            first = middle + 1;
        } else {
            return entry;
        }
    }
    return NULL;
}

static const struct capsule_stdlib_entry* entry_from_name(PyObject* name) {
    const char* utf8 = PyUnicode_AsUTF8(name);
    return utf8 ? stdlib_find(utf8) : NULL;
}

static PyObject* entry_filename(PyObject* name) {
    return PyUnicode_FromFormat("<capsule-stdlib>/%U.py", name);
}

static PyObject* stdlib_find_spec(PyObject* self, PyObject* arguments, PyObject* keywords) {
    static char* names[] = {"fullname", "path", "target", NULL};
    PyObject* fullname;
    PyObject* path = Py_None;
    PyObject* target = Py_None;
    if (!PyArg_ParseTupleAndKeywords(arguments, keywords, "O|OO:find_spec", names, &fullname, &path, &target)) {
        return NULL;
    }
    (void)path;
    (void)target;
    const struct capsule_stdlib_entry* entry = entry_from_name(fullname);
    if (!entry) {
        if (PyErr_Occurred()) {
            return NULL;
        }
        Py_RETURN_NONE;
    }

    PyObject* bootstrap = PyImport_ImportModule("_frozen_importlib");
    PyObject* spec_type = bootstrap ? PyObject_GetAttrString(bootstrap, "ModuleSpec") : NULL;
    PyObject* filename = spec_type ? entry_filename(fullname) : NULL;
    PyObject* positional = filename ? PyTuple_Pack(2, fullname, self) : NULL;
    PyObject* keyword = positional ? PyDict_New() : NULL;
    PyObject* package = (entry->flags & CAPSULE_STDLIB_PACKAGE) ? Py_True : Py_False;
    if (keyword && (PyDict_SetItemString(keyword, "origin", filename) || PyDict_SetItemString(keyword, "is_package", package))) {
        Py_CLEAR(keyword);
    }
    PyObject* spec = keyword ? PyObject_Call(spec_type, positional, keyword) : NULL;
    Py_XDECREF(keyword);
    Py_XDECREF(positional);
    Py_XDECREF(filename);
    Py_XDECREF(spec_type);
    Py_XDECREF(bootstrap);
    return spec;
}

static PyObject* stdlib_create_module(PyObject* self, PyObject* spec) {
    (void)self;
    (void)spec;
    Py_RETURN_NONE;
}

static PyObject* stdlib_exec_module(PyObject* self, PyObject* module) {
    (void)self;
    PyObject* name = PyObject_GetAttrString(module, "__name__");
    const struct capsule_stdlib_entry* entry = name ? entry_from_name(name) : NULL;
    if (!entry && !PyErr_Occurred()) {
        PyErr_Format(PyExc_ImportError, "no source for %R", name);
    }
    PyObject* filename = entry ? entry_filename(name) : NULL;
    PyObject* code = filename ? Py_CompileStringObject((const char*)stdlib_image + entry->source_offset, filename, Py_file_input, NULL, -1) : NULL;
    PyObject* globals = code ? PyModule_GetDict(module) : NULL;
    // Match exec(code, module.__dict__): PyEval_EvalCode alone does not insert
    // this key, which imports initiated by C extensions also consult.
    if (globals) {
        int present = PyDict_ContainsString(globals, "__builtins__");
        if (present < 0 || (!present && PyDict_SetItemString(globals, "__builtins__", PyEval_GetBuiltins()))) {
            globals = NULL;
        }
    }
    PyObject* result = globals ? PyEval_EvalCode(code, globals, globals) : NULL;
    Py_XDECREF(code);
    Py_XDECREF(filename);
    Py_XDECREF(name);
    if (!result) {
        return NULL;
    }
    Py_DECREF(result);
    Py_RETURN_NONE;
}

static PyObject* stdlib_is_package(PyObject* self, PyObject* name) {
    (void)self;
    const struct capsule_stdlib_entry* entry = entry_from_name(name);
    if (!entry) {
        if (!PyErr_Occurred()) {
            PyErr_Format(PyExc_ImportError, "no source for %R", name);
        }
        return NULL;
    }
    return PyBool_FromLong((entry->flags & CAPSULE_STDLIB_PACKAGE) != 0);
}

static PyObject* stdlib_get_filename(PyObject* self, PyObject* name) {
    (void)self;
    if (!entry_from_name(name)) {
        if (!PyErr_Occurred()) {
            PyErr_Format(PyExc_ImportError, "no source for %R", name);
        }
        return NULL;
    }
    return entry_filename(name);
}

static PyObject* stdlib_get_source(PyObject* self, PyObject* name) {
    (void)self;
    const struct capsule_stdlib_entry* entry = entry_from_name(name);
    if (!entry) {
        if (!PyErr_Occurred()) {
            PyErr_Format(PyExc_ImportError, "no source for %R", name);
        }
        return NULL;
    }
    return PyUnicode_DecodeUTF8((const char*)stdlib_image + entry->source_offset, entry->source_size, "strict");
}

static PyMethodDef stdlib_methods[] = {
    {"find_spec", (PyCFunction)(void*)stdlib_find_spec, METH_VARARGS | METH_KEYWORDS, NULL},
    {"create_module", stdlib_create_module, METH_O, NULL},
    {"exec_module", stdlib_exec_module, METH_O, NULL},
    {"is_package", stdlib_is_package, METH_O, NULL},
    {"get_filename", stdlib_get_filename, METH_O, NULL},
    {"get_source", stdlib_get_source, METH_O, NULL},
    {NULL, NULL, 0, NULL},
};

static struct PyModuleDef stdlib_module = {
    PyModuleDef_HEAD_INIT,
    .m_name = "_capsule_stdlib",
    .m_doc = "Read-only CPython standard library stored in Capsule memory.",
    // Every interpreter receives the same immutable packed image. Installation
    // is serialized before XDP attachment and only republishes identical
    // pointers, so the loader has no interpreter-owned mutable state.
    .m_size = 0,
    .m_methods = stdlib_methods,
};

static int validate_image(const void* image, size_t size) {
    if (!image || size < sizeof(struct capsule_stdlib_header)) {
        return -1;
    }
    const struct capsule_stdlib_header* header = image;
    if (memcmp(header->magic, "BPCPYLIB", 8) || header->version != 1 || header->count > (size - sizeof(*header)) / sizeof(struct capsule_stdlib_entry)) {
        return -1;
    }
    size_t names_at = sizeof(*header) + (size_t)header->count * sizeof(struct capsule_stdlib_entry);
    if (header->names_size > size - names_at || header->sources_size != size - names_at - header->names_size) {
        return -1;
    }
    const struct capsule_stdlib_entry* entries = (const void*)((const unsigned char*)image + sizeof(*header));
    const char* names = (const char*)image + names_at;
    for (uint32_t index = 0; index < header->count; ++index) {
        const struct capsule_stdlib_entry* entry = &entries[index];
        if (entry->name_offset >= header->names_size || !memchr(names + entry->name_offset, 0, header->names_size - entry->name_offset) ||
            entry->source_offset >= size || entry->source_size >= size - entry->source_offset ||
            ((const unsigned char*)image)[entry->source_offset + entry->source_size] != 0 || (entry->flags & ~CAPSULE_STDLIB_PACKAGE)) {
            return -1;
        }
        if (index && strcmp(names + entries[index - 1].name_offset, names + entry->name_offset) >= 0) {
            return -1;
        }
    }
    return 0;
}

int capsule_python_install_stdlib(const void* image, size_t size) {
    if (validate_image(image, size)) {
        PyErr_SetString(PyExc_ValueError, "invalid Capsule standard-library image");
        return -1;
    }
    stdlib_image = image;
    stdlib_header = image;
    stdlib_entries = (const void*)(stdlib_image + sizeof(*stdlib_header));
    stdlib_names = (const char*)stdlib_image + sizeof(*stdlib_header) + (size_t)stdlib_header->count * sizeof(*stdlib_entries);

    PyObject* loader = PyModule_Create(&stdlib_module);
    PyObject* sys = loader ? PyImport_ImportModule("sys") : NULL;
    PyObject* meta_path = sys ? PyObject_GetAttrString(sys, "meta_path") : NULL;
    int result = meta_path && PyList_Check(meta_path) ? PyList_Insert(meta_path, 0, loader) : -1;
    if (result && !PyErr_Occurred()) {
        PyErr_SetString(PyExc_RuntimeError, "sys.meta_path is unavailable");
    }
    Py_XDECREF(meta_path);
    Py_XDECREF(sys);
    Py_XDECREF(loader);
    return result;
}
