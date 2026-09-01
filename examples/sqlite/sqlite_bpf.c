// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
// Stock SQLite in the kernel.
//
// Stock amalgamation, soft-float SQL, Capsule's allocator, and a null VFS: the
// database and its temporary storage live in memory. The host reads results
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
    (void)v;
    static uint64_t seed = 0x9e3779b97f4a7c15ull;
    for (int i = 0; i < n; i++) {
        seed = seed * 6364136223846793005ull + 1442695040888963407ull;
        out[i] = (char)(seed >> 33);
    }
    return n;
}
static int vfs_sleep(sqlite3_vfs* v, int us) {
    (void)v;
    (void)us;
    return 0;
}
static int vfs_current_time_i64(sqlite3_vfs* v, sqlite3_int64* t) {
    (void)v;
    *t = 210866760000000ll; // an arbitrary fixed julian-ms epoch
    return SQLITE_OK;
}
static int vfs_open_fail(sqlite3_vfs* v, sqlite3_filename f, sqlite3_file* file, int flags, int* out) {
    (void)v;
    (void)f;
    (void)file;
    (void)flags;
    (void)out;
    return SQLITE_CANTOPEN; // this example deliberately has no file-backed databases
}
static int vfs_delete(sqlite3_vfs* v, const char* n, int s) {
    (void)v;
    (void)n;
    (void)s;
    return SQLITE_IOERR_DELETE;
}
static int vfs_access(sqlite3_vfs* v, const char* n, int f, int* out) {
    (void)v;
    (void)n;
    (void)f;
    *out = 0;
    return SQLITE_OK;
}
static int vfs_fullpath(sqlite3_vfs* v, const char* n, int sz, char* out) {
    (void)v;
    if (sz < 1) {
        return SQLITE_CANTOPEN;
    }
    int i = 0;
    for (; n[i] && i + 1 < sz; i++) {
        out[i] = n[i];
    }
    out[i] = 0;
    return SQLITE_OK;
}

static sqlite3_vfs null_vfs = {
    .iVersion = 2,
    .szOsFile = sizeof(sqlite3_file),
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

// ------------------------------------------------------------- example query
static int checksum_callback(void* arg, int ncol, char** vals, char** names) {
    (void)arg;
    (void)names;
    sctrl.rows++;
    for (int i = 0; i < ncol; i++) {
        for (const char* p = vals[i] ? vals[i] : "~"; *p; p++) {
            sctrl.checksum = sctrl.checksum * 31 + (unsigned char)*p;
        }
    }
    return 0;
}

static void sqlite_run_body(void) {
    sctrl.rows = 0;
    sctrl.checksum = 0;
    int rc = sqlite3_initialize();
    if (rc) {
        sctrl.sqlite_rc = rc;
        return;
    }

    sqlite3* db = 0;
    rc = sqlite3_open(":memory:", &db);
    if (rc) {
        goto close_database;
    }
    rc = sqlite3_exec(db, "PRAGMA temp_store=MEMORY;", 0, 0, 0);
    if (rc) {
        goto close_database;
    }
    rc = sqlite3_exec(db,
        "CREATE TABLE t(a INTEGER PRIMARY KEY, b INTEGER, c TEXT);"
        "WITH RECURSIVE r(i) AS (VALUES(1) UNION ALL SELECT i + 1 FROM r WHERE i < 500) "
        "INSERT INTO t SELECT i, i * i, 'row-' || i FROM r;",
        0, 0, 0);
    if (rc) {
        goto close_database;
    }
    rc = sqlite3_exec(db,
        "SELECT count(*), sum(b) FROM t;"
        "SELECT c FROM t WHERE a % 97 = 0 ORDER BY a DESC;"
        "SELECT b FROM t WHERE c LIKE 'row-1%' ORDER BY a LIMIT 5;"
        "SELECT 12.5 / 2.0;",
        checksum_callback, 0, 0);
close_database:
    if (db) {
        int close_rc = sqlite3_close(db);
        if (!rc && close_rc) {
            rc = close_rc;
        }
    }
    int shutdown_rc = sqlite3_shutdown();
    if (!rc && shutdown_rc) {
        rc = shutdown_rc;
    }
    sctrl.sqlite_rc = rc;
}

SEC("syscall")
int sqlite_run(void) {
    sctrl.capsule = capsule_call_void(sqlite_run_body);
    return 0;
}

SEC("syscall")
int sqlite_drain(void) {
    sctrl.capsule = capsule_continue_void(sctrl.capsule.continuation);
    return 0;
}

char _license[] SEC("license") = "GPL";
