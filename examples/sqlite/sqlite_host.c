// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
// Host side of the in-kernel SQLite example: run the built-in script in the
// kernel, then run the identical script on the host's own sqlite and compare
// row count and checksum.
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "bpf_capsule_host.h"

#include "sqlite_ctrl.h"

#include "sqlite.skel.h"

#define MAX_DRAINS 2000000

static uint64_t h_rows, h_sum;
static int host_cb(void* a, int n, char** v, char** names) {
    (void)a;
    (void)names;
    h_rows++;
    for (int i = 0; i < n; i++) {
        for (const char* p = v[i] ? v[i] : "~"; *p; p++) {
            h_sum = h_sum * 31 + (unsigned char)*p;
        }
    }
    return 0;
}

static uint64_t program_run_time(int program_fd) {
    struct bpf_prog_info info = {};
    unsigned int info_length = sizeof(info);
    return bpf_prog_get_info_by_fd(program_fd, &info, &info_length) ? 0 : info.run_time_ns;
}

static int run_native_reference(uint64_t* runtime_ns) {
    struct timespec begin;
    struct timespec end;
    sqlite3* database = NULL;
    int result = SQLITE_OK;

    clock_gettime(CLOCK_THREAD_CPUTIME_ID, &begin);
    result = sqlite3_open(":memory:", &database);
    if (result != SQLITE_OK) {
        fprintf(stderr, "native sqlite open failed: %s\n", database ? sqlite3_errmsg(database) : sqlite3_errstr(result));
        goto cleanup;
    }
    result = sqlite3_exec(database, "CREATE TABLE t(a INTEGER PRIMARY KEY, b INTEGER, c TEXT);", NULL, NULL, NULL);
    if (result != SQLITE_OK) {
        fprintf(stderr, "native sqlite create failed: %s\n", sqlite3_errmsg(database));
        goto cleanup;
    }
    for (int i = 1; i <= 500; ++i) {
        char* sql = sqlite3_mprintf("INSERT INTO t VALUES(%d, %d, 'row-' || %d);", i, i * i, i);
        if (!sql) {
            result = SQLITE_NOMEM;
            fprintf(stderr, "native sqlite insert formatting failed\n");
            goto cleanup;
        }
        result = sqlite3_exec(database, sql, NULL, NULL, NULL);
        sqlite3_free(sql);
        if (result != SQLITE_OK) {
            fprintf(stderr, "native sqlite insert failed: %s\n", sqlite3_errmsg(database));
            goto cleanup;
        }
    }
    result = sqlite3_exec(
        database,
        "SELECT count(*), sum(b) FROM t;"
        "SELECT c FROM t WHERE a % 97 = 0 ORDER BY a DESC;"
        "SELECT b FROM t WHERE c LIKE 'row-1%' LIMIT 5;",
        host_cb, NULL, NULL
    );
    if (result != SQLITE_OK) {
        fprintf(stderr, "native sqlite query failed: %s\n", sqlite3_errmsg(database));
        goto cleanup;
    }

cleanup:
    if (database) {
        int close_result = sqlite3_close(database);
        if (result == SQLITE_OK && close_result != SQLITE_OK) {
            fprintf(stderr, "native sqlite close failed: %s\n", sqlite3_errstr(close_result));
            result = close_result;
        }
    }
    clock_gettime(CLOCK_THREAD_CPUTIME_ID, &end);
    *runtime_ns = (uint64_t)(end.tv_sec - begin.tv_sec) * 1000000000ull + (uint64_t)(end.tv_nsec - begin.tv_nsec);
    return result == SQLITE_OK ? 0 : -1;
}

int main(int argc, char** argv) {
    (void)argv;
    if (argc != 1) {
        fprintf(stderr, "usage: sqlite\n");
        return 1;
    }

    struct sqlite* skeleton = sqlite__open();
    if (!skeleton) {
        fprintf(stderr, "open failed\n");
        return 1;
    }
    const struct bpf_capsule_config capsule_config = {
        .fiber_count = 1,
        .heap_bytes = 8ull << 20,
    };
    if (bpf_capsule_configure(skeleton->obj, capsule_config) || bpf_object__load_skeleton(skeleton->skeleton) ||
        bpf_capsule_finish_initialization(skeleton->obj)) {
        fprintf(stderr, "load failed\n");
        sqlite__destroy(skeleton);
        return 1;
    }
    volatile struct sqlite_bpf_ctrl* control = &skeleton->data_sctrl->sctrl;
    int drain_fd = bpf_program__fd(skeleton->progs.sqlite_drain);
    int run_fd = bpf_program__fd(skeleton->progs.sqlite_run);
    struct bpf_test_run_opts options = {.sz = sizeof(options)};

    // Kernel-side BPF runtime accounting: with stats enabled, run_time_ns
    // accumulates each program's real execution nanoseconds — never syscall
    // wall time.
    int stats_fd = bpf_enable_stats(BPF_STATS_RUN_TIME);
    if (bpf_prog_test_run_opts(run_fd, &options)) {
        perror("run");
        sqlite__destroy(skeleton);
        return 1;
    }
    unsigned long drains = 0;
    while (control->capsule.status == CAPSULE_PENDING) {
        if (drains == MAX_DRAINS) {
            fprintf(stderr, "gave up after %lu drains: computation still pending\n", drains);
            sqlite__destroy(skeleton);
            return 1;
        }
        if (bpf_prog_test_run_opts(drain_fd, &options)) {
            perror("drain");
            sqlite__destroy(skeleton);
            return 1;
        }
        drains++;
    }
    if (control->capsule.status != CAPSULE_OK) {
        if (control->capsule.status == CAPSULE_EXITED && control->capsule.code < 0) {
            fprintf(stderr, "capsule stopped: %s (%lld)\n", bpf_capsule_error_string(control->capsule.code), (long long)control->capsule.code);
        } else if (control->capsule.status == CAPSULE_EXITED) {
            fprintf(stderr, "capsule exited with code %lld\n", (long long)control->capsule.code);
        } else {
            fprintf(stderr, "capsule status=%s\n", bpf_capsule_status_string(control->capsule.status));
        }
        sqlite__destroy(skeleton);
        return 1;
    }
    uint64_t kernel_ns = program_run_time(run_fd) + program_run_time(drain_fd);
    if (stats_fd >= 0) {
        close(stats_fd);
    }

    // The same script against the host's own sqlite. Thread CPU time is the
    // native analog of the kernel's run_time_ns.
    uint64_t native_ns = 0;
    if (run_native_reference(&native_ns)) {
        sqlite__destroy(skeleton);
        return 1;
    }

    printf("rows=%llu checksum=%llx\n", (unsigned long long)control->rows, (unsigned long long)control->sum);
    if (stats_fd >= 0) {
        fprintf(stderr, "kernel execution: %llu ns, native execution: %llu ns\n", (unsigned long long)kernel_ns, (unsigned long long)native_ns);
    } else {
        fprintf(stderr, "native execution: %llu ns\n", (unsigned long long)native_ns);
    }
    fprintf(stderr, "continuation drains: %lu\n", drains);
    if (control->sqlite_rc) {
        char error[17] = {0};
        memcpy(error + 0, (const void*)&control->sqlite_error0, 8);
        memcpy(error + 8, (const void*)&control->sqlite_error1, 8);
        fprintf(stderr, "sqlite error prefix: %s\n", error);
    }
    int pass = control->status == SQLITE_STAGE_COMPLETE && control->capsule.status == CAPSULE_OK && control->rows == h_rows && control->sum == h_sum;
    if (!pass) {
        fprintf(
            stderr, "kernel and native disagree: kernel status=%llu rows=%llu sum=%llx sqlite_rc=%llu, native rows=%llu sum=%llx\n",
            (unsigned long long)control->status, (unsigned long long)control->rows, (unsigned long long)control->sum, (unsigned long long)control->sqlite_rc,
            (unsigned long long)h_rows, (unsigned long long)h_sum
        );
    }
    sqlite__destroy(skeleton);
    return pass ? 0 : 1;
}
