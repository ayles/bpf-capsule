// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
// Run the built-in SQLite workload in the kernel and check its result.
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>

#include "bpf_capsule_host.h"

#include "sqlite_ctrl.h"

#include "sqlite.skel.h"

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

int main(int argc, char** argv) {
    (void)argv;
    if (argc != 1) {
        fprintf(stderr, "usage: sqlite\n");
        return 1;
    }
    unsigned long max_drains = 0;
    if (read_max_drains(&max_drains)) {
        return 1;
    }

    int result = 1;
    struct sqlite* skeleton = sqlite__open();
    struct bpf_capsule capsule = {0};
    if (!skeleton) {
        fprintf(stderr, "open failed\n");
        goto cleanup;
    }
    if (bpf_capsule_configure(&capsule, skeleton->obj,
            (struct bpf_capsule_config){
                .fiber_count = 1,
                .heap_bytes = 8ull << 20,
            }) ||
        bpf_object__load_skeleton(skeleton->skeleton) || bpf_capsule_initialize(&capsule)) {
        fprintf(stderr, "load failed\n");
        goto cleanup;
    }
    volatile struct sqlite_bpf_ctrl* control = &skeleton->data_sctrl->sctrl;
    int drain_fd = bpf_program__fd(skeleton->progs.sqlite_drain);
    int run_fd = bpf_program__fd(skeleton->progs.sqlite_run);
    struct bpf_test_run_opts options = {.sz = sizeof(options)};

    if (bpf_prog_test_run_opts(run_fd, &options)) {
        perror("run");
        goto cleanup;
    }
    unsigned long drains = 0;
    while (control->capsule.status == CAPSULE_PENDING) {
        if (drains == max_drains) {
            fprintf(stderr, "computation is still pending after %lu drains; set BPF_CAPSULE_MAX_DRAINS to permit more\n", drains);
            goto cleanup;
        }
        if (bpf_prog_test_run_opts(drain_fd, &options)) {
            perror("drain");
            goto cleanup;
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
        goto cleanup;
    }

    printf("rows=%llu checksum=%llx\n", (unsigned long long)control->rows, (unsigned long long)control->checksum);
    fprintf(stderr, "continuation drains: %lu\n", drains);
    int pass = !control->sqlite_rc && control->rows == 12 && control->checksum == 0x693506f4cc70de84ull;
    if (!pass) {
        fprintf(stderr, "unexpected SQLite result: rc=%d rows=%llu checksum=%llx\n", control->sqlite_rc, (unsigned long long)control->rows,
            (unsigned long long)control->checksum);
    }
    result = pass ? 0 : 1;

cleanup:
    (void)bpf_capsule_release(&capsule);
    sqlite__destroy(skeleton);
    return result;
}
