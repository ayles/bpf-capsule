// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#include <Python.h>
#include <errno.h>
#include <stdint.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#include "bpf_capsule.h"
#include "python_ctrl.h"
#include "python_stdlib.h"

struct python_ctrl python_control SEC(".data.python");

static int python_clock_ns(clockid_t clock, uint64_t* result) {
    uint64_t monotonic = bpf_ktime_get_ns();
    if (clock == CLOCK_MONOTONIC) {
        *result = monotonic;
        return 0;
    }
    if (clock == CLOCK_REALTIME) {
        *result = monotonic + (uint64_t)python_control.realtime_offset_ns;
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

static void record_exception(const char* fallback) {
    copy_text(python_control.error, sizeof(python_control.error), fallback);
    PyObject* exception = PyErr_GetRaisedException();
    if (!exception) {
        return;
    }
    PyObject* text = PyObject_Str(exception);
    const char* utf8 = text ? PyUnicode_AsUTF8(text) : NULL;
    if (utf8) {
        copy_text(python_control.error, sizeof(python_control.error), utf8);
    }
    Py_XDECREF(text);
    Py_DECREF(exception);
}

// CPython's ordinary stdout/stderr stack eventually reaches write(). Keep the
// platform call synchronous and append to host-visible Capsule memory.
ssize_t write(int fd, const void* data, size_t size) {
    if (fd != STDOUT_FILENO && fd != STDERR_FILENO) {
        errno = EBADF;
        return -1;
    }
    size_t begin = python_control.output_size;
    size_t available = begin < python_control.output_capacity ? python_control.output_capacity - begin : 0;
    size_t copied = size < available ? size : available;
    for (size_t index = 0; index < copied; ++index) {
        python_control.output[begin + index] = ((const char*)data)[index];
    }
    python_control.output_size += size;
    return (ssize_t)size;
}

static void python_execute(void) {
    if (!python_control.stdlib_image || !python_control.stdlib_size || !python_control.script || !python_control.output || !python_control.output_capacity) {
        capsule_exit(1);
    }

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
        config.hash_seed = python_control.hash_seed;
        config.write_bytecode = 0;
        // The interpreter is embedded: do not discover an executable through
        // PATH or the current directory. Imports use the packed image.
        status = PyConfig_SetString(&config, &config.executable, L"/capsule/python");
        if (!PyStatus_Exception(status)) {
            status = Py_InitializeFromConfig(&config);
        }
        PyConfig_Clear(&config);
    }
    if (PyStatus_Exception(status)) {
        copy_text(python_control.error, sizeof(python_control.error), status.err_msg);
        capsule_exit(2);
    }
    if (capsule_python_install_stdlib(python_control.stdlib_image, python_control.stdlib_size)) {
        record_exception("cannot install the standard library");
        capsule_exit(3);
    }
    if (PyRun_SimpleString(python_control.script)) {
        record_exception("Python script failed");
        capsule_exit(4);
    }
}

SEC("syscall")
int python_start(void) {
    python_control.execution = capsule_call_void(python_execute);
    return python_control.execution.status;
}

SEC("syscall")
int python_drain(void) {
    python_control.execution = capsule_continue_void(python_control.execution.continuation);
    return python_control.execution.status;
}

char _license[] SEC("license") = "GPL";
