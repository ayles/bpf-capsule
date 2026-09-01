// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
// Run a no_std Rust allocation/soft-float workload, then surface a Rust panic.

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "bpf_capsule_host.h"

#include "rust_ctrl.h"
#include "rust.skel.h"

static int drain_to_completion(
    int drain_fd, struct bpf_test_run_opts* options, volatile const struct capsule_result* capsule, unsigned long max_drains, unsigned long* drains) {
    unsigned long run_drains = 0;
    while (capsule->status == CAPSULE_PENDING) {
        if (run_drains == max_drains) {
            fprintf(stderr, "computation is still pending after %lu drains; set BPF_CAPSULE_MAX_DRAINS to permit more\n", run_drains);
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

static int read_max_drains(unsigned long* result) {
    const char* text = getenv("BPF_CAPSULE_MAX_DRAINS");
    *result = 0;
    if (!text || !*text) {
        return 0;
    }
    char* end = NULL;
    errno = 0;
    unsigned long value = strtoul(text, &end, 10);
    if (text[0] < '0' || text[0] > '9' || errno || !end || *end) {
        fprintf(stderr, "BPF_CAPSULE_MAX_DRAINS must be a non-negative integer\n");
        return -1;
    }
    *result = value;
    return 0;
}

static void report_failure(const volatile struct capsule_result* capsule) {
    if (capsule->status == CAPSULE_EXITED && capsule->code < 0) {
        fprintf(stderr, "capsule stopped: %s (%lld)\n", bpf_capsule_error_string(capsule->code), (long long)capsule->code);
    } else if (capsule->status == CAPSULE_EXITED) {
        fprintf(stderr, "capsule exited with code %lld\n", (long long)capsule->code);
    } else {
        fprintf(stderr, "capsule status=%s\n", bpf_capsule_status_string(capsule->status));
    }
}

int main(int argc, char** argv) {
    (void)argv;
    if (argc != 1) {
        fprintf(stderr, "usage: rust\n");
        return 1;
    }
    unsigned long max_drains = 0;
    if (read_max_drains(&max_drains)) {
        return 1;
    }

    int result = 1;
    struct rust* skeleton = rust__open();
    struct bpf_capsule capsule = {0};
    if (!skeleton) {
        fprintf(stderr, "open failed\n");
        goto cleanup;
    }
    if (bpf_capsule_configure(&capsule, skeleton->obj,
            (struct bpf_capsule_config){
                .fiber_count = 1,
                .heap_bytes = 8u << 20,
            }) ||
        bpf_object__load_skeleton(skeleton->skeleton) || bpf_capsule_initialize(&capsule)) {
        fprintf(stderr, "load failed: %s\n", strerror(errno));
        goto cleanup;
    }

    volatile struct rust_bpf_ctrl* control = &skeleton->data_rctrl->rctrl;
    int entry_fd = bpf_program__fd(skeleton->progs.rust_entry);
    int drain_fd = bpf_program__fd(skeleton->progs.rust_drain);
    int panic_entry_fd = bpf_program__fd(skeleton->progs.rust_panic_entry);
    int panic_drain_fd = bpf_program__fd(skeleton->progs.rust_panic_drain);
    if (entry_fd < 0 || drain_fd < 0 || panic_entry_fd < 0 || panic_drain_fd < 0) {
        fprintf(stderr, "BPF object is missing a Rust program\n");
        goto cleanup;
    }

    struct bpf_test_run_opts options = {.sz = sizeof(options)};
    unsigned long drains = 0;
    if (bpf_prog_test_run_opts(entry_fd, &options)) {
        perror("run");
        goto cleanup;
    }
    if (drain_to_completion(drain_fd, &options, &control->capsule, max_drains, &drains)) {
        goto cleanup;
    }
    if (control->capsule.status != CAPSULE_OK) {
        report_failure(&control->capsule);
        goto cleanup;
    }
    printf("Rust MLP checksum: %llx\n", (unsigned long long)control->checksum);

    if (bpf_prog_test_run_opts(panic_entry_fd, &options)) {
        perror("panic run");
        goto cleanup;
    }
    if (drain_to_completion(panic_drain_fd, &options, &control->capsule, max_drains, &drains)) {
        goto cleanup;
    }
    printf("Rust panic: status=%s code=%lld\n", bpf_capsule_status_string(control->capsule.status), (long long)control->capsule.code);
    if (control->capsule.status != CAPSULE_EXITED || control->capsule.code != 101) {
        report_failure(&control->capsule);
        goto cleanup;
    }
    fprintf(stderr, "continuation drains: %lu\n", drains);
    result = 0;

cleanup:
    if (skeleton) {
        (void)bpf_capsule_release(&capsule);
        rust__destroy(skeleton);
    }
    return result;
}
