// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
// One isolated CPython interpreter per Capsule fiber and a borrowed
// XDP-packet adapter. Initialization runs on one fiber and creates every
// interpreter; each fiber then binds its own thread state to its interpreter,
// so CPython's thread-local state is simply fiber-local.
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#include <Python.h>
#include <errno.h>
#include <stdint.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#include "bpf_capsule.h"
#include "python_stdlib.h"
#include "python_xdp_internal.h"

// Prepared for every fiber by the initializing one.
struct python_fiber_state {
    PyInterpreterState* interpreter;
    PyObject* packet_observer;
};

static struct python_fiber_state python_fibers[BPF_CAPSULE_MAX_FIBERS];
// A fiber's own thread state in its interpreter, bound on first use. The
// thread state an interpreter was created with stays with the creating fiber.
static _Thread_local PyThreadState* python_thread_state;
static _Thread_local size_t python_output_size;
static int python_initializing;

static int python_clock_ns(clockid_t clock, uint64_t* result) {
    uint64_t monotonic = bpf_ktime_get_ns();
    if (clock == CLOCK_MONOTONIC) {
        *result = monotonic;
        return 0;
    }
    if (clock == CLOCK_REALTIME) {
        *result = monotonic + (uint64_t)python_xdp_control.realtime_offset_ns;
        return 0;
    }
    errno = EINVAL;
    return -1;
}

int clock_gettime(clockid_t clock, struct timespec* value) {
    if (!value) {
        errno = EFAULT;
        return -1;
    }
    uint64_t nanoseconds;
    if (python_clock_ns(clock, &nanoseconds)) {
        return -1;
    }
    value->tv_sec = (time_t)(nanoseconds / 1000000000u);
    value->tv_nsec = (long)(nanoseconds % 1000000000u);
    return 0;
}

int clock_getres(clockid_t clock, struct timespec* resolution) {
    if (clock != CLOCK_REALTIME && clock != CLOCK_MONOTONIC) {
        errno = EINVAL;
        return -1;
    }
    if (resolution) {
        resolution->tv_sec = 0;
        resolution->tv_nsec = 1;
    }
    return 0;
}

int gettimeofday(struct timeval* value, void* timezone) {
    (void)timezone;
    if (!value) {
        errno = EFAULT;
        return -1;
    }
    uint64_t nanoseconds;
    if (python_clock_ns(CLOCK_REALTIME, &nanoseconds)) {
        return -1;
    }
    value->tv_sec = (time_t)(nanoseconds / 1000000000u);
    value->tv_usec = (suseconds_t)((nanoseconds % 1000000000u) / 1000u);
    return 0;
}

static struct python_fiber_state* python_fiber_slot(void) {
    unsigned int index = capsule_fiber_index();
    if (index >= BPF_CAPSULE_MAX_FIBERS) {
        capsule_exit(1);
    }
    return &python_fibers[index];
}

static void copy_text(char* destination, size_t capacity, const char* source) {
    size_t index = 0;
    if (source) {
        while (index + 1 < capacity && source[index]) {
            destination[index] = source[index];
            ++index;
        }
    }
    if (capacity) {
        destination[index] = 0;
    }
}

static void exchange_copy(size_t buffer_offset, size_t begin, const char* text, size_t length) {
    size_t available = begin < PYTHON_XDP_OUTPUT_CAPACITY ? PYTHON_XDP_OUTPUT_CAPACITY - begin : 0;
    size_t copied = length < available ? length : available;
    for (size_t index = 0; index < copied; ++index) {
        char byte = text[index];
        struct python_xdp_exchange* exchange = bpf_map_lookup_elem(&python_exchange_by_cpu, &python_exchange_key);
        if (!exchange) {
            capsule_exit(1);
        }
        unsigned long at = (unsigned long)(begin + index);
        asm volatile("" : "+r"(at));
        at &= PYTHON_XDP_OUTPUT_CAPACITY - 1u;
        asm volatile("" : "+r"(buffer_offset));
        buffer_offset &= PYTHON_XDP_OUTPUT_CAPACITY;
        ((char*)exchange)[buffer_offset + at] = byte;
    }
}

ssize_t write(int fd, const void* data, size_t size) {
    if (fd != STDOUT_FILENO && fd != STDERR_FILENO) {
        errno = EBADF;
        return -1;
    }
    size_t begin = python_output_size;
    python_output_size += size;
    exchange_copy(0, begin, data, size);
    return (ssize_t)size;
}

static void report_exception(const char* fallback) {
    const char* message = fallback;
    PyObject* exception = PyErr_GetRaisedException();
    PyObject* text = exception ? PyObject_Str(exception) : NULL;
    const char* utf8 = text ? PyUnicode_AsUTF8(text) : NULL;
    if (utf8) {
        message = utf8;
    }
    if (python_initializing) {
        copy_text(python_xdp_control.error, sizeof(python_xdp_control.error), message);
    }
    size_t length = strlen(message);
    struct python_xdp_exchange* exchange = bpf_map_lookup_elem(&python_exchange_by_cpu, &python_exchange_key);
    if (exchange) {
        exchange->error_size = length;
        exchange_copy(PYTHON_XDP_OUTPUT_CAPACITY, 0, message, length);
    }
    Py_XDECREF(text);
    Py_XDECREF(exception);
}

// Runs the observer script in the current thread state's interpreter.
static void python_prepare_observer(struct python_fiber_state* fiber) {
    if (capsule_python_install_stdlib(python_xdp_control.stdlib_image, python_xdp_control.stdlib_size)) {
        report_exception("cannot install the standard library");
        capsule_exit(3);
    }

    PyObject* main_module = PyImport_AddModule("__main__");
    PyObject* globals = main_module ? PyModule_GetDict(main_module) : NULL;
    PyObject* executed = globals ? PyRun_String(python_xdp_control.script, Py_file_input, globals, globals) : NULL;
    PyObject* observer = executed ? PyDict_GetItemString(globals, "observe") : NULL;
    if (!observer || !PyCallable_Check(observer)) {
        if (!PyErr_Occurred()) {
            PyErr_SetString(PyExc_TypeError, "observer must define callable observe(packet)");
        }
        Py_XDECREF(executed);
        report_exception("cannot compile the packet observer");
        capsule_exit(4);
    }
    Py_INCREF(observer);
    fiber->interpreter = PyInterpreterState_Get();
    fiber->packet_observer = observer;
    Py_DECREF(executed);
}

void python_initialize(void) {
    if (!python_xdp_control.stdlib_image || !python_xdp_control.stdlib_size || !python_xdp_control.script) {
        capsule_exit(1);
    }
    python_initializing = 1;

    if (capsule_python_configure_sqlite()) {
        capsule_exit(2);
    }
    PyPreConfig preconfig;
    PyPreConfig_InitIsolatedConfig(&preconfig);
    preconfig.utf8_mode = 1;
    PyStatus status = Py_PreInitialize(&preconfig);

    PyConfig config;
    if (!PyStatus_Exception(status)) {
        PyConfig_InitIsolatedConfig(&config);
        config.buffered_stdio = 0;
        config.configure_c_stdio = 0;
        config.install_signal_handlers = 0;
        config.module_search_paths_set = 1;
        config.site_import = 0;
        config.use_hash_seed = 1;
        config.hash_seed = python_xdp_control.hash_seed;
        config.write_bytecode = 0;
        // The interpreter is embedded: do not discover an executable through
        // PATH or the current directory. Imports use the packed image.
        status = PyConfig_SetString(&config, &config.executable, L"/capsule/python-xdp");
        if (!PyStatus_Exception(status)) {
            status = Py_InitializeFromConfig(&config);
        }
        PyConfig_Clear(&config);
    }
    if (PyStatus_Exception(status)) {
        copy_text(python_xdp_control.error, sizeof(python_xdp_control.error), status.err_msg);
        capsule_exit(2);
    }
    // The main interpreter belongs to this fiber, with the thread state it
    // was created on.
    struct python_fiber_state* main_fiber = python_fiber_slot();
    python_thread_state = PyThreadState_Get();
    python_prepare_observer(main_fiber);

    const PyInterpreterConfig interpreter_config = {
        .use_main_obmalloc = 0,
        .allow_fork = 0,
        .allow_exec = 0,
        .allow_threads = 0,
        .allow_daemon_threads = 0,
        .check_multi_interp_extensions = 1,
        .gil = PyInterpreterConfig_OWN_GIL,
    };
    unsigned int count = capsule_fiber_count();
    for (unsigned int index = 0; index < count; ++index) {
        if (&python_fibers[index] == main_fiber) {
            continue;
        }
        PyThreadState* thread_state = NULL;
        status = Py_NewInterpreterFromConfig(&thread_state, &interpreter_config);
        if (PyStatus_Exception(status)) {
            copy_text(python_xdp_control.error, sizeof(python_xdp_control.error), status.err_msg);
            capsule_exit(2);
        }
        python_prepare_observer(&python_fibers[index]);
    }

    (void)PyEval_SaveThread();
    python_initializing = 0;
}

static int copy_packet(unsigned char* destination, size_t length) {
    for (size_t index = 0; index < length; ++index) {
        struct xdp_md* ctx = capsule_borrowed_ctx();
        unsigned char* data = (unsigned char*)(long)ctx->data;
        unsigned char* data_end = (unsigned char*)(long)ctx->data_end;
        size_t at = index;
        asm volatile("" : "+r"(at));
        at &= PYTHON_XDP_PACKET_CAPACITY - 1u;
        if (data + at + 1 > data_end) {
            return -1;
        }
        destination[index] = data[at];
    }
    return 0;
}

size_t python_execute_packet(size_t packet_size) {
    struct python_fiber_state* fiber = python_fiber_slot();
    if (!fiber->interpreter || !fiber->packet_observer) {
        capsule_exit(1);
    }
    if (!python_thread_state) {
        python_thread_state = PyThreadState_New(fiber->interpreter);
        if (!python_thread_state) {
            capsule_exit(1);
        }
    }
    PyEval_RestoreThread(python_thread_state);
    python_output_size = 0;
    PyObject* packet = PyBytes_FromStringAndSize(NULL, (Py_ssize_t)packet_size);
    if (!packet || copy_packet((unsigned char*)PyBytes_AS_STRING(packet), packet_size)) {
        Py_XDECREF(packet);
        if (!PyErr_Occurred()) {
            PyErr_SetString(PyExc_RuntimeError, "packet changed during inspection");
        }
        report_exception("cannot copy the packet");
        capsule_exit(1);
    }
    PyObject* result = PyObject_CallOneArg(fiber->packet_observer, packet);
    Py_DECREF(packet);
    if (!result) {
        report_exception("packet observer failed");
        capsule_exit(1);
    }
    Py_DECREF(result);
    (void)PyEval_SaveThread();
    return python_output_size;
}
