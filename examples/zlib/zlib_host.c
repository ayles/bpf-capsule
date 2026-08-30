// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
// Host side of the in-kernel zlib example: prepare one compressed input,
// inflate it in the kernel, and compare the result byte for byte.
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <zlib.h>

#include "bpf_capsule_host.h"

#include "zlib_ctrl.h"

#include "zlib.skel.h"

#define MAX_DRAINS 2000000

// Run one entry and drain budget-driven continuations until the capsule
// reaches a terminal state. Returns zero only when the capsule reports
// CAPSULE_OK.
static int run_to_completion(
    int run_fd, int drain_fd, struct bpf_test_run_opts* options, volatile const struct capsule_result* capsule, unsigned long* drains) {
    if (bpf_prog_test_run_opts(run_fd, options)) {
        perror("run");
        return -1;
    }
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
    if (capsule->status != CAPSULE_OK) {
        if (capsule->status == CAPSULE_EXITED && capsule->code < 0) {
            fprintf(stderr, "capsule stopped: %s (%lld)\n", bpf_capsule_error_string(capsule->code), (long long)capsule->code);
        } else if (capsule->status == CAPSULE_EXITED) {
            fprintf(stderr, "capsule exited with code %lld\n", (long long)capsule->code);
        } else {
            fprintf(stderr, "capsule status=%s\n", bpf_capsule_status_string(capsule->status));
        }
        return -1;
    }
    return 0;
}

int main(int argc, char** argv) {
    if (argc > 2) {
        fprintf(stderr, "usage: zlib [BYTES]\n");
        return 1;
    }
    char* size_end = NULL;
    errno = 0;
    size_t n = argc > 1 ? strtoul(argv[1], &size_end, 0) : (2u << 20);
    if (!n || n > UINT_MAX || errno || (size_end && *size_end)) {
        fprintf(stderr, "BYTES must be an integer from 1 through %u\n", UINT_MAX);
        return 1;
    }

    int result = 1;
    struct zlib* skeleton = NULL;
    struct bpf_capsule capsule = {0};
    unsigned char* data = NULL;
    unsigned char* comp = NULL;

    // Compressible but not trivial: runs of a pattern with an LCG sprinkle.
    data = malloc(n);
    if (!data) {
        fprintf(stderr, "cannot allocate %zu input bytes\n", n);
        goto cleanup;
    }
    unsigned int lcg = 12345;
    for (size_t i = 0; i < n; i++) {
        lcg = lcg * 1103515245 + 12345;
        data[i] = (i & 0xfff) < 0xe00 ? (unsigned char)(i >> 6) : (unsigned char)(lcg >> 16);
    }

    uLongf clen = compressBound(n);
    if (!clen || clen > UINT_MAX) {
        fprintf(stderr, "compressed input bound does not fit zlib's 32-bit stream length\n");
        goto cleanup;
    }
    comp = malloc(clen);
    if (!comp || compress2(comp, &clen, data, n, 6) != Z_OK || !clen || clen > UINT_MAX) {
        fprintf(stderr, "deflate failed\n");
        goto cleanup;
    }
    fprintf(stderr, "in: %zu bytes -> %lu compressed\n", n, (unsigned long)clen);

    // The whole heap is one host-reserved prefix carved into three buffers;
    // the in-kernel inflate works out of the staged workspace, not malloc.
    size_t output_offset = (clen + 15u) & ~(size_t)15u;
    size_t workspace_offset = (output_offset + n + 15u) & ~(size_t)15u;
    size_t heap_bytes = workspace_offset + ZLIB_WORKSPACE_BYTES;

    skeleton = zlib__open();
    if (!skeleton) {
        fprintf(stderr, "open failed\n");
        goto cleanup;
    }
    if (bpf_capsule_configure(&capsule, skeleton->obj,
            (struct bpf_capsule_config){
                .fiber_count = 1,
                .heap_bytes = heap_bytes,
                .reserved_bytes = heap_bytes,
            }) ||
        bpf_object__load_skeleton(skeleton->skeleton) || bpf_capsule_initialize(&capsule)) {
        fprintf(stderr, "load failed: %s\n", strerror(errno));
        goto cleanup;
    }
    volatile struct zlib_bpf_ctrl* control = &skeleton->data_zctrl->zctrl;

    unsigned char* reserved = bpf_capsule_memory_reserved_start(&capsule);
    unsigned char* input = reserved;
    unsigned char* output = reserved + output_offset;
    unsigned char* workspace = reserved + workspace_offset;
    if (bpf_capsule_memcpy(&capsule, input, comp, clen)) {
        fprintf(stderr, "cannot write zlib input: %s\n", strerror(errno));
        goto cleanup;
    }
    control->input = input;
    control->input_size = clen;
    control->output = output;
    control->output_capacity = n;
    control->workspace = workspace;

    int drain_fd = bpf_program__fd(skeleton->progs.zlib_drain);
    int run_fd = bpf_program__fd(skeleton->progs.zlib_run);
    if (drain_fd < 0 || run_fd < 0) {
        fprintf(stderr, "BPF object is missing a zlib program\n");
        goto cleanup;
    }
    struct bpf_test_run_opts options = {.sz = sizeof(options)};
    unsigned long continuation_drains = 0;
    if (run_to_completion(run_fd, drain_fd, &options, &control->capsule, &continuation_drains)) {
        goto cleanup;
    }
    int pass = control->status == Z_STREAM_END && control->output_size == n && control->capsule.status == CAPSULE_OK && memcmp(output, data, n) == 0;
    if (!pass) {
        fprintf(stderr, "inflate failed: status=%d output=%zu expected=%zu\n", control->status, control->output_size, n);
    } else {
        printf("stock zlib: %lu compressed bytes -> %zu bytes\n", (unsigned long)clen, n);
        fprintf(stderr, "continuation drains: %lu\n", continuation_drains);
    }
    result = pass ? 0 : 1;

cleanup:
    if (skeleton) {
        (void)bpf_capsule_release(&capsule);
        zlib__destroy(skeleton);
    }
    free(comp);
    free(data);
    return result;
}
