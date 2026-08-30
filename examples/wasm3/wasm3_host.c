// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
// Host side of the in-kernel wasm3 example: compress one buffer, let the Wasm
// module inflate it in the kernel, and compare the output byte for byte.
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "bpf_capsule_host.h"

#include <zlib.h>

#include "wasm3_ctrl.h"

#include "wasm3.skel.h"

enum {
    MAX_DRAINS = 500000,
    WASM3_HEAP_BYTES = 4u << 20,
};

static void make_input(unsigned char* data, size_t size) {
    unsigned lcg = 12345;
    for (size_t i = 0; i < size; i++) {
        lcg = lcg * 1103515245u + 12345u;
        data[i] = (i & 0xfff) < 0xe00 ? (unsigned char)(i >> 6) : (unsigned char)(lcg >> 16);
    }
}

int main(int argc, char** argv) {
    if (argc > 2) {
        fprintf(stderr, "usage: wasm3 [BYTES]\n");
        return 1;
    }
    char* size_end = NULL;
    errno = 0;
    size_t input_size = argc > 1 ? strtoul(argv[1], &size_end, 0) : 65536;
    if (!input_size || input_size > WASM_ZLIB_GUEST_OUTPUT_CAPACITY || errno || (size_end && *size_end)) {
        fprintf(stderr, "BYTES must be an integer from 1 through %u\n", (unsigned int)WASM_ZLIB_GUEST_OUTPUT_CAPACITY);
        return 1;
    }

    int exit_code = 1;
    unsigned char* input = malloc(input_size);
    uLongf compressed_capacity = compressBound(input_size);
    unsigned char* compressed = malloc(compressed_capacity);
    struct wasm3* skeleton = NULL;
    struct bpf_capsule capsule = {0};
    if (!input || !compressed) {
        fprintf(stderr, "cannot allocate wasm3 input buffers\n");
        goto cleanup;
    }
    make_input(input, input_size);
    uLongf compressed_size = compressed_capacity;
    if (compress2(compressed, &compressed_size, input, input_size, 6) != Z_OK) {
        fprintf(stderr, "cannot compress wasm3 input\n");
        goto cleanup;
    }
    if (!compressed_size || compressed_size > WASM_ZLIB_GUEST_INPUT_CAPACITY) {
        fprintf(stderr, "compressed wasm3 input exceeds the guest's %u-byte input buffer\n", (unsigned int)WASM_ZLIB_GUEST_INPUT_CAPACITY);
        goto cleanup;
    }

    skeleton = wasm3__open();
    if (!skeleton) {
        fprintf(stderr, "open failed\n");
        goto cleanup;
    }
    size_t output_offset = ((size_t)compressed_size + 15u) & ~(size_t)15u;
    size_t reserved_bytes = output_offset + input_size;
    if (bpf_capsule_configure(&capsule, skeleton->obj,
            (struct bpf_capsule_config){
                .fiber_count = 1,
                .heap_bytes = reserved_bytes + WASM3_HEAP_BYTES,
                .reserved_bytes = reserved_bytes,
            }) ||
        bpf_object__load_skeleton(skeleton->skeleton) || bpf_capsule_initialize(&capsule)) {
        fprintf(stderr, "load failed: %s\n", strerror(errno));
        goto cleanup;
    }

    volatile struct wasm3_bpf_ctrl* control = &skeleton->data_w3ctrl->w3ctrl;
    unsigned char* staged_input = bpf_capsule_memory_reserved_start(&capsule);
    unsigned char* output = staged_input + output_offset;
    if (bpf_capsule_memcpy(&capsule, staged_input, compressed, compressed_size)) {
        fprintf(stderr, "cannot stage wasm3 input: %s\n", strerror(errno));
        goto cleanup;
    }
    control->input = staged_input;
    control->input_size = compressed_size;
    control->output = output;
    control->output_capacity = input_size;

    int drain_fd = bpf_program__fd(skeleton->progs.wasm3_drain);
    int run_fd = bpf_program__fd(skeleton->progs.wasm3_zlib_run);
    if (drain_fd < 0 || run_fd < 0) {
        fprintf(stderr, "BPF object is missing a wasm3 program\n");
        goto cleanup;
    }
    struct bpf_test_run_opts options = {.sz = sizeof(options)};

    if (bpf_prog_test_run_opts(run_fd, &options)) {
        perror("run");
        goto cleanup;
    }
    unsigned long drains = 0;
    while (control->capsule.status == CAPSULE_PENDING) {
        if (drains == MAX_DRAINS) {
            fprintf(stderr, "gave up after %lu drains: computation still pending\n", drains);
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
    int pass = control->zlib_status == Z_STREAM_END && control->output_size == input_size && !memcmp(output, input, input_size);
    if (!pass) {
        fprintf(stderr, "Wasm inflate failed: status=%d output=%zu expected=%zu\n", control->zlib_status, control->output_size, input_size);
    } else {
        printf("stock zlib Wasm: %zu -> %lu compressed bytes\n", input_size, (unsigned long)compressed_size);
        fprintf(stderr, "continuation drains: %lu\n", drains);
    }
    exit_code = pass ? 0 : 1;

cleanup:
    if (skeleton) {
        (void)bpf_capsule_release(&capsule);
        wasm3__destroy(skeleton);
    }
    free(compressed);
    free(input);
    return exit_code;
}
