// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
// SQLite in the kernel — the toolchain's third program.
//
// Stock amalgamation, integer-only build (no floating point in BPF), memsys5
// over the configured Capsule heap, and a null VFS: the database lives
// in :memory: and temp space is SQLITE_TEMP_STORE=3. The host reads results
// from the ctrl map; entries follow the driver convention (one void managed
// call, results written by managed code).
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#include "bpf_capsule.h"

#include "sqlite3.h"
#include "sqlite_ctrl.h"

struct sqlite_bpf_ctrl sctrl SEC(".data.sctrl");

// ---------------------------------------------------------------- null VFS
static int vfs_randomness(sqlite3_vfs* v, int n, char* out) {
    static uint64_t seed = 0x9e3779b97f4a7c15ull;
    for (int i = 0; i < n; i++) {
        seed = seed * 6364136223846793005ull + 1442695040888963407ull;
        out[i] = (char)(seed >> 33);
    }
    return n;
}
static int vfs_sleep(sqlite3_vfs* v, int us) {
    return 0;
}
static int vfs_current_time_i64(sqlite3_vfs* v, sqlite3_int64* t) {
    *t = 210866760000000ll; // an arbitrary fixed julian-ms epoch
    return SQLITE_OK;
}
static int vfs_open_fail(sqlite3_vfs* v, sqlite3_filename f, sqlite3_file* file, int flags, int* out) {
    return SQLITE_CANTOPEN; // :memory: + TEMP_STORE=3 never open files
}
static int vfs_delete(sqlite3_vfs* v, const char* n, int s) {
    return SQLITE_OK;
}
static int vfs_access(sqlite3_vfs* v, const char* n, int f, int* out) {
    *out = 0;
    return SQLITE_OK;
}
static int vfs_fullpath(sqlite3_vfs* v, const char* n, int sz, char* out) {
    unsigned long i = 0;
    for (; n[i] && i + 1 < (unsigned long)sz; i++) {
        out[i] = n[i];
    }
    out[i] = 0;
    return SQLITE_OK;
}

static sqlite3_vfs null_vfs = {
    .iVersion = 2,
    .szOsFile = 8,
    .mxPathname = 64,
    .zName = "bpf-null",
    .xOpen = vfs_open_fail,
    .xDelete = vfs_delete,
    .xAccess = vfs_access,
    .xFullPathname = vfs_fullpath,
    .xRandomness = vfs_randomness,
    .xSleep = vfs_sleep,
    .xCurrentTimeInt64 = vfs_current_time_i64,
};

int sqlite3_os_init(void) {
    return sqlite3_vfs_register(&null_vfs, 1);
}
int sqlite3_os_end(void) {
    return SQLITE_OK;
}

// ------------------------------------------------------------------ the test
static int sum_cb(void* arg, int ncol, char** vals, char** names) {
    sctrl.rows++;
    for (int i = 0; i < ncol; i++) {
        for (const char* p = vals[i] ? vals[i] : "~"; *p; p++) {
            sctrl.sum = sctrl.sum * 31 + (unsigned char)*p;
        }
    }
    return 0;
}

static void save_sqlite_error(sqlite3* db) {
    const char* text = db ? sqlite3_errmsg(db) : "no database handle";
    // Scalar snapshots avoid making a pointer into the control map live
    // across a diagnostic copy loop (map-value pointers cannot be persisted
    // in the managed frame). Packed byte by byte, stopping at the
    // terminator: the message may be shorter than the 16 bytes captured,
    // and a wide load would read past it.
    uint64_t words[2] = {0, 0};
    for (int i = 0; i < 16 && text[i]; i++) {
        words[i >> 3] |= (uint64_t)(unsigned char)text[i] << ((i & 7) * 8);
    }
    sctrl.sqlite_error0 = words[0];
    sctrl.sqlite_error1 = words[1];
}

static void sqlite_run_body(void) {
    sctrl.status = SQLITE_STAGE_STARTED;
    uint64_t heap_bytes = capsule_heap_size();
    if (heap_bytes > 0x7fffffffull) {
        sctrl.sqlite_rc = SQLITE_NOMEM;
        return;
    }
    sctrl.sqlite_rc = sqlite3_config(SQLITE_CONFIG_HEAP, capsule_heap_start(), (int)heap_bytes, 64);
    if (sctrl.sqlite_rc) {
        return;
    }
    sctrl.status = SQLITE_STAGE_HEAP_CONFIGURED;
    sctrl.sqlite_rc = sqlite3_initialize();
    if (sctrl.sqlite_rc) {
        return;
    }
    sctrl.status = SQLITE_STAGE_INITIALIZED;

    sqlite3* db = 0;
    sctrl.sqlite_rc = sqlite3_open(":memory:", &db);
    if (sctrl.sqlite_rc) {
        return;
    }
    sctrl.status = SQLITE_STAGE_DATABASE_OPEN;

    sctrl.sqlite_rc = sqlite3_exec(db, "CREATE TABLE t(a INTEGER PRIMARY KEY, b INTEGER, c TEXT);", 0, 0, 0);
    if (sctrl.sqlite_rc) {
        save_sqlite_error(db);
        return;
    }
    sctrl.status = SQLITE_STAGE_TABLE_CREATED;

    for (int i = 1; i <= 500; i++) {
        char* sql = sqlite3_mprintf("INSERT INTO t VALUES(%d, %d, 'row-' || %d);", i, i * i, i);
        int rc = sql ? sqlite3_exec(db, sql, 0, 0, 0) : SQLITE_NOMEM;
        sctrl.sqlite_rc = rc;
        sqlite3_free(sql);
        if (rc) {
            save_sqlite_error(db);
            return;
        }
    }
    sctrl.status = SQLITE_STAGE_ROWS_INSERTED;

    sctrl.rows = 0;
    sctrl.sum = 0;
    sctrl.sqlite_rc = sqlite3_exec(
        db,
        "SELECT count(*), sum(b) FROM t;"
        "SELECT c FROM t WHERE a % 97 = 0 ORDER BY a DESC;"
        "SELECT b FROM t WHERE c LIKE 'row-1%' LIMIT 5;",
        sum_cb, 0, 0
    );
    if (sctrl.sqlite_rc) {
        save_sqlite_error(db);
        return;
    }
    sctrl.status = SQLITE_STAGE_QUERIES_COMPLETE;

    sqlite3_close(db);
    sctrl.status = SQLITE_STAGE_COMPLETE;
}

SEC("syscall")
int sqlite_run() {
    sctrl.capsule = capsule_call_void(sqlite_run_body);
    return 0;
}

SEC("syscall")
int sqlite_drain() {
    sctrl.capsule = capsule_continue_void(sctrl.capsule.continuation);
    return 0;
}

char _license[] SEC("license") = "GPL";
