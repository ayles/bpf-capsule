// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
// Host side of the Rust example: run the in-kernel MLP inference, run the
// natively compiled build of the identical lib.rs in this process, compare
// the output checksums (folded over exact f32 bit patterns) byte for byte,
// then show a Rust panic surfacing as an ordinary guest exit.
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "bpf_capsule_host.h"

#include "rust_ctrl.h"

#include "rust.skel.h"

#define MAX_DRAINS 100000

// The natively built staticlib of the same lib.rs.
extern uint64_t rust_run(uint64_t n);
// The prebuilt native liballoc references the unwind personality even under
// panic=abort; nothing here unwinds, so an empty symbol satisfies the link.
void rust_eh_personality(void) {
}

static uint64_t program_run_time(int program_fd) {
    struct bpf_prog_info info = {};
    unsigned int info_length = sizeof(info);
    return bpf_prog_get_info_by_fd(program_fd, &info, &info_length) ? 0 : info.run_time_ns;
}

static int drain_to_completion(int drain_fd, struct bpf_test_run_opts* options, volatile const struct capsule_result* capsule, unsigned long* drains) {
    unsigned long run_drains = 0;
    while (capsule->status == CAPSULE_PENDING) {
        if (run_drains == MAX_DRAINS) {
            fprintf(stderr, "gave up after %lu drains: computation still pending\n", run_drains);
            return -1;
        }
        if (bpf_prog_test_run_opts(drain_fd, options)) {
            perror("drain");
            return -1;
        }
        run_drains++;
        (*drains)++;
    }
    return 0;
}

int main(int argc, char** argv) {
    (void)argv;
    if (argc != 1) {
        fprintf(stderr, "usage: rust\n");
        return 1;
    }

    struct rust* skeleton = rust__open();
    if (!skeleton) {
        fprintf(stderr, "open failed\n");
        return 1;
    }
    struct bpf_object* obj = skeleton->obj;
    const struct bpf_capsule_config capsule_config = {
        .fiber_count = 1,
        .heap_bytes = 8ull << 20,
    };
    if (bpf_capsule_configure(obj, capsule_config) || bpf_object__load_skeleton(skeleton->skeleton) || bpf_capsule_finish_initialization(skeleton->obj)) {
        fprintf(stderr, "load failed\n");
        rust__destroy(skeleton);
        return 1;
    }

    volatile struct rust_bpf_ctrl* control = &skeleton->data_rctrl->rctrl;

    int entry_fd = bpf_program__fd(skeleton->progs.rust_entry);
    int drain_fd = bpf_program__fd(skeleton->progs.rust_drain);
    int panic_entry_fd = bpf_program__fd(skeleton->progs.rust_panic_entry);
    struct bpf_test_run_opts options = {.sz = sizeof(options)};
    unsigned long continuation_drains = 0;

    // Kernel-side BPF runtime accounting: with stats enabled, run_time_ns
    // accumulates each program's real execution nanoseconds — never syscall
    // wall time.
    int stats_fd = bpf_enable_stats(BPF_STATS_RUN_TIME);
    if (bpf_prog_test_run_opts(entry_fd, &options)) {
        perror("run");
        rust__destroy(skeleton);
        return 1;
    }
    if (drain_to_completion(drain_fd, &options, &control->capsule, &continuation_drains)) {
        rust__destroy(skeleton);
        return 1;
    }
    if (control->capsule.status != CAPSULE_OK) {
        if (control->capsule.status == CAPSULE_EXITED && control->capsule.code < 0) {
            fprintf(stderr, "capsule stopped: %s (%lld)\n", bpf_capsule_error_string(control->capsule.code), (long long)control->capsule.code);
        } else if (control->capsule.status == CAPSULE_EXITED) {
            fprintf(stderr, "capsule exited with code %lld\n", (long long)control->capsule.code);
        } else {
            fprintf(stderr, "capsule status=%s\n", bpf_capsule_status_string(control->capsule.status));
        }
        rust__destroy(skeleton);
        return 1;
    }
    uint64_t kernel_ns = program_run_time(entry_fd) + program_run_time(drain_fd);

    // Thread CPU time is the native analog of the kernel's run_time_ns.
    struct timespec t0, t1;
    clock_gettime(CLOCK_THREAD_CPUTIME_ID, &t0);
    uint64_t want = rust_run(1000);
    clock_gettime(CLOCK_THREAD_CPUTIME_ID, &t1);
    uint64_t native_ns = (uint64_t)(t1.tv_sec - t0.tv_sec) * 1000000000ull + (uint64_t)(t1.tv_nsec - t0.tv_nsec);

    printf("mlp checksum: %llx\n", (unsigned long long)control->result);
    if (stats_fd >= 0) {
        fprintf(stderr, "kernel execution: %llu ns, native execution: %llu ns\n", (unsigned long long)kernel_ns, (unsigned long long)native_ns);
    } else {
        fprintf(stderr, "native execution: %llu ns\n", (unsigned long long)native_ns);
    }
    int pass = control->status == RUST_STAGE_COMPLETE && control->capsule.status == CAPSULE_OK && control->result == want;
    if (!pass) {
        fprintf(
            stderr, "kernel and native disagree: kernel status=%llu result=%llx, native result=%llx\n", (unsigned long long)control->status,
            (unsigned long long)control->result, (unsigned long long)want
        );
    }

    // The second entry panics on purpose: the bpf-capsule-rt panic handler
    // ends the computation with capsule_exit(101), matching a std Rust
    // process's panic exit status.
    if (bpf_prog_test_run_opts(panic_entry_fd, &options)) {
        perror("panic run");
        rust__destroy(skeleton);
        return 1;
    }
    if (drain_to_completion(drain_fd, &options, &control->capsule, &continuation_drains)) {
        rust__destroy(skeleton);
        return 1;
    }
    printf("panic demo: status=%s code=%lld\n", bpf_capsule_status_string(control->capsule.status), (long long)control->capsule.code);
    fprintf(stderr, "continuation drains: %lu\n", continuation_drains);
    pass = pass && control->capsule.status == CAPSULE_EXITED && control->capsule.code == 101;
    if (stats_fd >= 0) {
        close(stats_fd);
    }
    rust__destroy(skeleton);
    return pass ? 0 : 1;
}
