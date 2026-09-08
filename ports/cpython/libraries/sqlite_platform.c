// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
// SQLite's public embedding interfaces, shared by both Python examples.
#include "sqlite3.h"
#include "bpf_capsule.h"
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <unistd.h>

struct sqlite3_mutex {
    unsigned owner;
    unsigned depth;
};

static struct sqlite3_mutex static_mutexes[SQLITE_MUTEX_STATIC_VFS3 + 1];

static int mutex_init(void) {
    return SQLITE_OK;
}
static int mutex_end(void) {
    return SQLITE_OK;
}

static sqlite3_mutex* mutex_alloc(int kind) {
    return kind >= SQLITE_MUTEX_STATIC_MAIN ? &static_mutexes[kind] : calloc(1, sizeof(sqlite3_mutex));
}

static void mutex_free(sqlite3_mutex* mutex) {
    free(mutex);
}

static int mutex_try(sqlite3_mutex* mutex) {
    unsigned owner = capsule_fiber_index() + 1;
    unsigned expected = 0;
    if (__atomic_load_n(&mutex->owner, __ATOMIC_RELAXED) != owner &&
        !__atomic_compare_exchange_n(&mutex->owner, &expected, owner, 0, __ATOMIC_ACQUIRE, __ATOMIC_RELAXED)) {
        return SQLITE_BUSY;
    }
    ++mutex->depth;
    return SQLITE_OK;
}

static void mutex_enter(sqlite3_mutex* mutex) {
    while (mutex_try(mutex) != SQLITE_OK) {
    }
}

static void mutex_leave(sqlite3_mutex* mutex) {
    if (!--mutex->depth) {
        __atomic_store_n(&mutex->owner, 0, __ATOMIC_RELEASE);
    }
}

static int mutex_held(sqlite3_mutex* mutex) {
    return !mutex || __atomic_load_n(&mutex->owner, __ATOMIC_RELAXED) == capsule_fiber_index() + 1;
}

static int mutex_notheld(sqlite3_mutex* mutex) {
    return !mutex || !mutex_held(mutex);
}

// Called once before Py_InitializeFromConfig, before any interpreter can
// import sqlite3. SQLite may then initialize concurrently using these locks.
int capsule_python_configure_sqlite(void) {
    static const sqlite3_mutex_methods methods = {
        mutex_init,
        mutex_end,
        mutex_alloc,
        mutex_free,
        mutex_enter,
        mutex_try,
        mutex_leave,
        mutex_held,
        mutex_notheld,
    };
    return sqlite3_config(SQLITE_CONFIG_MUTEX, &methods);
}

static int file_open(sqlite3_vfs* vfs, sqlite3_filename name, sqlite3_file* file, int flags, int* output) {
    (void)vfs;
    (void)name;
    (void)file;
    (void)flags;
    (void)output;
    return SQLITE_CANTOPEN;
}

static int file_delete(sqlite3_vfs* vfs, const char* name, int sync) {
    (void)vfs;
    (void)name;
    (void)sync;
    return SQLITE_IOERR_DELETE;
}

static int file_access(sqlite3_vfs* vfs, const char* name, int flags, int* result) {
    (void)vfs;
    (void)name;
    (void)flags;
    *result = 0;
    return SQLITE_OK;
}

static int file_fullpath(sqlite3_vfs* vfs, const char* name, int size, char* result) {
    (void)vfs;
    size_t length = strlen(name);
    if (length >= (size_t)size) {
        return SQLITE_CANTOPEN;
    }
    memcpy(result, name, length + 1);
    return SQLITE_OK;
}

static int randomness(sqlite3_vfs* vfs, int size, char* result) {
    (void)vfs;
    int offset = 0;
    while (offset < size) {
        int count = size - offset > 256 ? 256 : size - offset;
        if (getentropy(result + offset, (size_t)count)) {
            break;
        }
        offset += count;
    }
    return offset;
}

static int sleep_unavailable(sqlite3_vfs* vfs, int microseconds) {
    (void)vfs;
    (void)microseconds;
    return 0; // No time spent sleeping; SQLite's callback returns elapsed time.
}

static int current_time(sqlite3_vfs* vfs, sqlite3_int64* result) {
    (void)vfs;
    struct timeval time;
    if (gettimeofday(&time, NULL)) {
        return SQLITE_ERROR;
    }
    *result = 210866760000000LL + (sqlite3_int64)time.tv_sec * 1000 + time.tv_usec / 1000;
    return SQLITE_OK;
}

static sqlite3_vfs vfs = {
    .iVersion = 2,
    .szOsFile = sizeof(sqlite3_file),
    .mxPathname = 1024,
    .zName = "capsule-memory",
    .xOpen = file_open,
    .xDelete = file_delete,
    .xAccess = file_access,
    .xFullPathname = file_fullpath,
    .xRandomness = randomness,
    .xSleep = sleep_unavailable,
    .xCurrentTimeInt64 = current_time,
};

int sqlite3_os_init(void) {
    return sqlite3_vfs_register(&vfs, 1);
}
int sqlite3_os_end(void) {
    return SQLITE_OK;
}
