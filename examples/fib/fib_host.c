// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
// The smallest complete Capsule host: configure, load with libbpf, run one
// recursive computation in the kernel, and report the kernel-measured
// execution time.
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <stdio.h>
#include <unistd.h>

#include "bpf_capsule_host.h"
#include "fib.h"
#include "fib.skel.h"

int main(void) {
    struct fib* skeleton = fib__open();
    if (!skeleton) {
        fprintf(stderr, "open failed\n");
        return 1;
    }
    const struct bpf_capsule_config capsule_config = {
        .fiber_count = 1,
        .heap_bytes = 0,
    };
    if (bpf_capsule_configure(skeleton->obj, capsule_config) || bpf_object__load_skeleton(skeleton->skeleton) ||
        bpf_capsule_finish_initialization(skeleton->obj)) {
        fprintf(stderr, "could not load and initialize the BPF object\n");
        fib__destroy(skeleton);
        return 1;
    }

    // The skeleton exposes each sectioned global as a typed field, and its
    // generated static asserts already pin the layout against the object.
    // volatile: the kernel writes these bytes outside the compiler's view.
    volatile struct fib_state* state = &skeleton->data_fib->fib_state;

    state->input = 20;
    // Kernel-side BPF runtime accounting: with stats enabled, the kernel
    // accumulates each program's real execution time in run_time_ns — the
    // program's own nanoseconds, not syscall wall time.
    int stats_fd = bpf_enable_stats(BPF_STATS_RUN_TIME);
    struct bpf_test_run_opts options = {.sz = sizeof(options)};
    int run_fd = bpf_program__fd(skeleton->progs.fib_run);
    int error = bpf_prog_test_run_opts(run_fd, &options);
    int ok = !error && state->result.status == CAPSULE_OK && state->output == 6765;
    if (!ok) {
        // Name the failure instead of only failing. A larger input than the
        // single in-kernel drive span would report "pending" here: this
        // example has no drain entry on purpose — see expr_drain in
        // examples/standalone for the continuation loop.
        if (!error && state->result.status == CAPSULE_EXITED && state->result.code < 0) {
            fprintf(stderr, "capsule stopped: %s (%lld)\n", bpf_capsule_error_string(state->result.code), (long long)state->result.code);
        } else if (!error && state->result.status == CAPSULE_EXITED) {
            fprintf(stderr, "capsule exited with code %lld\n", (long long)state->result.code);
        } else {
            fprintf(stderr, "run failed: capsule status=%s\n", bpf_capsule_status_string(state->result.status));
        }
        fib__destroy(skeleton);
        return 1;
    }
    printf("fib(%u) = %u\n", state->input, state->output);
    struct bpf_prog_info info = {};
    unsigned int info_length = sizeof(info);
    if (stats_fd >= 0 && !bpf_prog_get_info_by_fd(run_fd, &info, &info_length)) {
        fprintf(stderr, "kernel execution: %llu ns\n", (unsigned long long)info.run_time_ns);
        close(stats_fd);
    }
    fib__destroy(skeleton);
    return 0;
}
