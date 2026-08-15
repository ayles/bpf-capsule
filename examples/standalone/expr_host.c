// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
// Host side of the standalone example: load the object, write the expression
// into the guest-published input buffer, drive the kernel to completion, and
// compare against the same evaluator compiled natively.
//
// Depends only on libbpf and the maps and programs defined in expr_bpf.c —
// nothing here reaches back into the BPF Capsule source tree.
#include <bpf/bpf.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "bpf_capsule_host.h"
#include "expr_ctrl.h"
#include "expr.h"

#include "expr.skel.h"

#define EXPR_INPUT_MAX 4096
#define MAX_DRAINS 200000

static uint64_t program_run_time(int program_fd) {
    struct bpf_prog_info info = {};
    unsigned int info_length = sizeof(info);
    return bpf_prog_get_info_by_fd(program_fd, &info, &info_length) ? 0 : info.run_time_ns;
}

int main(int argc, char** argv) {
    if (argc > 2) {
        fprintf(stderr, "usage: expr [EXPRESSION]\n");
        return 1;
    }

    // Default input: a parenthesis tower 64 levels deep, value 65. The
    // verifier permits no recursion at any depth, and even this modest input
    // cannot fit the native 512-byte BPF stack — this is the demonstration.
    static char expr[EXPR_INPUT_MAX];
    size_t len;
    if (argc > 1) {
        len = strlen(argv[1]);
        if (len == 0 || len > sizeof(expr)) {
            fprintf(stderr, "expression must be 1..%zu bytes\n", sizeof(expr));
            return 1;
        }
        memcpy(expr, argv[1], len);
    } else {
        const int depth = 64;
        char* w = expr;
        for (int i = 0; i < depth; i++) {
            *w++ = '(';
            *w++ = '1';
            *w++ = '+';
        }
        *w++ = '1';
        for (int i = 0; i < depth; i++) {
            *w++ = ')';
        }
        len = (size_t)(w - expr);
    }

    struct expr* skeleton = expr__open();
    if (!skeleton) {
        fprintf(stderr, "open failed\n");
        return 1;
    }
    struct bpf_object* obj = skeleton->obj;
    const struct bpf_capsule_config capsule_config = {
        .fiber_count = 1,
        .heap_bytes = 1ull << 20,
    };

    // The lifecycle is three separate verbs: Capsule configuration before
    // load, libbpf's own skeleton load, Capsule memory initialization after.
    if (bpf_capsule_configure(obj, capsule_config) || bpf_object__load_skeleton(skeleton->skeleton) || bpf_capsule_finish_initialization(obj)) {
        fprintf(stderr, "load failed\n");
        expr__destroy(skeleton);
        return 1;
    }

    // The skeleton exposes each sectioned global as a typed field, and its
    // generated static asserts already pin the layout against the object.
    // volatile: the kernel writes these bytes outside the compiler's view.
    volatile struct expr_bpf_ctrl* control = &skeleton->data_ectrl->ectrl;

    // One memory view for the object's lifetime; bulk transfers go through it.
    struct bpf_capsule_memory memory;
    if (bpf_capsule_memory(obj, &memory)) {
        fprintf(stderr, "cannot map Capsule memory\n");
        expr__destroy(skeleton);
        return 1;
    }

    // Stage the input: expr_prepare publishes the guest input buffer, the
    // host writes the expression bytes to that ordinary Capsule address.
    struct bpf_test_run_opts options = {.sz = sizeof(options)};
    unsigned long drains = 0; // capped so a wedged run cannot spin forever
    int prepare_fd = bpf_program__fd(skeleton->progs.expr_prepare);
    int run_fd = bpf_program__fd(skeleton->progs.expr_run);
    int drain_fd = bpf_program__fd(skeleton->progs.expr_drain);
    if (bpf_prog_test_run_opts(prepare_fd, &options) || control->capsule.status != CAPSULE_OK) {
        fprintf(stderr, "cannot publish the input buffer\n");
        expr__destroy(skeleton);
        return 1;
    }
    if (len > control->input.capacity || bpf_capsule_memory_write(&memory, control->input.address, expr, len)) {
        fprintf(stderr, "staging failed: %s\n", strerror(errno));
        expr__destroy(skeleton);
        return 1;
    }
    control->input.size = len;

    // With BPF statistics enabled, the delta over entry plus drain programs
    // is execution inside the kernel, not syscall wall time.
    int stats_fd = bpf_enable_stats(BPF_STATS_RUN_TIME);
    uint64_t kernel_before = program_run_time(run_fd) + program_run_time(drain_fd);
    if (bpf_prog_test_run_opts(run_fd, &options)) {
        perror("run");
        if (stats_fd >= 0) {
            close(stats_fd);
        }
        expr__destroy(skeleton);
        return 1;
    }
    while (control->capsule.status == CAPSULE_PENDING) {
        if (drains == MAX_DRAINS) {
            fprintf(stderr, "gave up after %lu drains: computation still pending\n", drains);
            if (stats_fd >= 0) {
                close(stats_fd);
            }
            expr__destroy(skeleton);
            return 1;
        }
        if (bpf_prog_test_run_opts(drain_fd, &options)) {
            perror("drain");
            if (stats_fd >= 0) {
                close(stats_fd);
            }
            expr__destroy(skeleton);
            return 1;
        }
        drains++;
    }
    uint64_t kernel_ns = program_run_time(run_fd) + program_run_time(drain_fd) - kernel_before;
    if (stats_fd >= 0) {
        close(stats_fd);
    }
    if (control->capsule.status != CAPSULE_OK) {
        if (control->capsule.status == CAPSULE_EXITED && control->capsule.code < 0) {
            fprintf(stderr, "capsule stopped: %s (%lld)\n", bpf_capsule_error_string(control->capsule.code), (long long)control->capsule.code);
        } else if (control->capsule.status == CAPSULE_EXITED) {
            fprintf(stderr, "capsule exited with code %lld\n", (long long)control->capsule.code);
        } else {
            fprintf(stderr, "capsule status=%s\n", bpf_capsule_status_string(control->capsule.status));
        }
        expr__destroy(skeleton);
        return 1;
    }
    // The same sources, natively. Equal results are required, not compared
    // by eye: the workload is deterministic integer C, so any divergence is
    // a compiler bug, not noise.
    int64_t host_value = 0;
    unsigned long host_error = 0;
    struct timespec native_begin;
    struct timespec native_end;
    clock_gettime(CLOCK_THREAD_CPUTIME_ID, &native_begin);
    int host_rc = expr_eval(expr, len, &host_value, &host_error);
    clock_gettime(CLOCK_THREAD_CPUTIME_ID, &native_end);
    uint64_t native_ns = (uint64_t)(native_end.tv_sec - native_begin.tv_sec) * 1000000000ull + (uint64_t)(native_end.tv_nsec - native_begin.tv_nsec);

    if (stats_fd >= 0) {
        fprintf(stderr, "kernel execution: %llu ns, native execution: %llu ns\n", (unsigned long long)kernel_ns, (unsigned long long)native_ns);
    } else {
        fprintf(stderr, "native execution: %llu ns\n", (unsigned long long)native_ns);
    }

    int pass;
    if (host_rc == 0) {
        pass = control->capsule.status == CAPSULE_OK && control->status == EXPR_STAGE_DONE && control->value == host_value;
        if (pass) {
            printf("%lld\n", (long long)control->value);
        } else {
            fprintf(
                stderr, "kernel and native disagree: kernel status=%llu value=%lld, native value=%lld\n", (unsigned long long)control->status,
                (long long)control->value, (long long)host_value
            );
        }
    } else {
        pass = control->capsule.status == CAPSULE_OK && control->status == EXPR_ERROR_PARSE && control->error_at == host_error;
        if (pass) {
            printf("parse error at byte %llu\n", (unsigned long long)control->error_at);
        } else {
            fprintf(
                stderr, "kernel and native disagree: kernel status=%llu error_at=%llu, native error_at=%lu\n", (unsigned long long)control->status,
                (unsigned long long)control->error_at, host_error
            );
        }
    }
    expr__destroy(skeleton);
    return pass ? 0 : 1;
}
