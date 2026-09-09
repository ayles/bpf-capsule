// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
// The SQL runner shared by the Capsule guest and the native comparison build:
// the stock amalgamation over an in-memory-only VFS, executing one script of
// statements and writing every result row into a buffer, tab-separated. Both
// builds include this file once; only where the buffers live differs.
#pragma once

#include <stdint.h>
#include <string.h>

#include "sqlite3.h"

#include "sqlite_ctrl.h"

// ---- null VFS: no files, a fixed clock, a deterministic random source -------

static int sqlite_runner_randomness(sqlite3_vfs* vfs, int count, char* out) {
    (void)vfs;
    static uint64_t seed = 0x9e3779b97f4a7c15ull;
    for (int i = 0; i < count; i++) {
        seed = seed * 6364136223846793005ull + 1442695040888963407ull;
        out[i] = (char)(seed >> 33);
    }
    return count;
}

static int sqlite_runner_sleep(sqlite3_vfs* vfs, int microseconds) {
    (void)vfs;
    (void)microseconds;
    return 0;
}

static int sqlite_runner_current_time(sqlite3_vfs* vfs, sqlite3_int64* time) {
    (void)vfs;
    *time = 210866760000000ll; // an arbitrary fixed julian-ms epoch
    return SQLITE_OK;
}

static int sqlite_runner_open(sqlite3_vfs* vfs, sqlite3_filename name, sqlite3_file* file, int flags, int* out) {
    (void)vfs;
    (void)name;
    (void)file;
    (void)flags;
    (void)out;
    return SQLITE_CANTOPEN; // only :memory: databases exist here
}

static int sqlite_runner_delete(sqlite3_vfs* vfs, const char* name, int sync) {
    (void)vfs;
    (void)name;
    (void)sync;
    return SQLITE_IOERR_DELETE;
}

static int sqlite_runner_access(sqlite3_vfs* vfs, const char* name, int flags, int* out) {
    (void)vfs;
    (void)name;
    (void)flags;
    *out = 0;
    return SQLITE_OK;
}

static int sqlite_runner_full_path(sqlite3_vfs* vfs, const char* name, int size, char* out) {
    (void)vfs;
    if (size < 1) {
        return SQLITE_CANTOPEN;
    }
    int i = 0;
    for (; name[i] && i + 1 < size; i++) {
        out[i] = name[i];
    }
    out[i] = 0;
    return SQLITE_OK;
}

static sqlite3_vfs sqlite_runner_vfs = {
    .iVersion = 2,
    .szOsFile = sizeof(sqlite3_file),
    .mxPathname = 64,
    .zName = "capsule-null",
    .xOpen = sqlite_runner_open,
    .xDelete = sqlite_runner_delete,
    .xAccess = sqlite_runner_access,
    .xFullPathname = sqlite_runner_full_path,
    .xRandomness = sqlite_runner_randomness,
    .xSleep = sqlite_runner_sleep,
    .xCurrentTimeInt64 = sqlite_runner_current_time,
};

int sqlite3_os_init(void) {
    return sqlite3_vfs_register(&sqlite_runner_vfs, 1);
}

int sqlite3_os_end(void) {
    return SQLITE_OK;
}

// ---- the script -------------------------------------------------------------

// Sizes keep counting past the capacity so the host can report truncation.
static void sqlite_runner_append(struct sqlite_buffer* buffer, const char* text, size_t length) {
    size_t begin = buffer->size;
    size_t copied = begin < buffer->capacity ? buffer->capacity - begin : 0;
    if (copied > length) {
        copied = length;
    }
    if (copied) {
        memcpy(buffer->address + begin, text, copied);
    }
    buffer->size = length > SIZE_MAX - begin ? SIZE_MAX : begin + length;
}

// One result row per line, columns separated by tabs, NULL as an empty field.
static int sqlite_runner_row(void* argument, int columns, char** values, char** names) {
    (void)names;
    struct sqlite_buffer* output = argument;
    for (int i = 0; i < columns; i++) {
        if (i) {
            sqlite_runner_append(output, "\t", 1);
        }
        if (values[i]) {
            sqlite_runner_append(output, values[i], strlen(values[i]));
        }
    }
    sqlite_runner_append(output, "\n", 1);
    return 0;
}

// Executes the NUL-terminated script against a fresh in-memory database.
// Returns SQLite's result code; on failure the message is in the error buffer.
static int sqlite_runner_run(const struct sqlite_buffer* script, struct sqlite_buffer* output, struct sqlite_buffer* error) {
    output->size = 0;
    error->size = 0;
    int rc = sqlite3_initialize();
    if (rc) {
        return rc;
    }
    sqlite3* database = 0;
    char* message = 0;
    rc = sqlite3_open(":memory:", &database);
    if (!rc) {
        rc = sqlite3_exec(database, "PRAGMA temp_store=MEMORY;", 0, 0, 0);
    }
    if (!rc) {
        rc = sqlite3_exec(database, script->address, sqlite_runner_row, output, &message);
    }
    if (rc) {
        const char* text = message ? message : database ? sqlite3_errmsg(database) : sqlite3_errstr(rc);
        sqlite_runner_append(error, text, strlen(text));
    }
    sqlite3_free(message);
    if (database) {
        int close_rc = sqlite3_close(database);
        if (!rc) {
            rc = close_rc;
        }
    }
    int shutdown_rc = sqlite3_shutdown();
    return rc ? rc : shutdown_rc;
}
