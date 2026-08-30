// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
// Run one JavaScript file with batch stdin and direct Capsule-memory output.

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "bpf_capsule_host.h"

#include "quickjs_ctrl.h"
#include "quickjs.skel.h"

enum {
    QUICKJS_MAX_DRAINS = 2000000,
    QUICKJS_OUTPUT_BYTES = 1u << 20,
    QUICKJS_ERROR_BYTES = 64u << 10,
    QUICKJS_HEAP_BYTES = 16u << 20,
};

static char* read_stream(FILE* file, size_t* size) {
    size_t capacity = 64u << 10;
    size_t used = 0;
    char* data = malloc(capacity + 1);
    if (!data) {
        return NULL;
    }
    for (;;) {
        if (used == capacity) {
            if (capacity > (SIZE_MAX - 1) / 2) {
                free(data);
                errno = EOVERFLOW;
                return NULL;
            }
            capacity *= 2;
            char* grown = realloc(data, capacity + 1);
            if (!grown) {
                free(data);
                return NULL;
            }
            data = grown;
        }
        size_t got = fread(data + used, 1, capacity - used, file);
        used += got;
        if (!got) {
            if (ferror(file)) {
                free(data);
                return NULL;
            }
            data[used] = '\0';
            *size = used;
            return data;
        }
    }
}

static int reserve_buffer(size_t* total, size_t size, size_t* offset) {
    if (*total > SIZE_MAX - 15u) {
        return -1;
    }
    size_t aligned = (*total + 15u) & ~(size_t)15u;
    if (size > SIZE_MAX - aligned) {
        return -1;
    }
    *offset = aligned;
    *total = aligned + size;
    return 0;
}

int main(int argc, char** argv) {
    if (argc != 2) {
        fprintf(stderr, "usage: quickjs SCRIPT\n");
        return 2;
    }

    int result = 1;
    char* script = NULL;
    char* input = NULL;
    struct quickjs* skeleton = NULL;
    struct bpf_capsule capsule = {0};

    FILE* file = fopen(argv[1], "rb");
    size_t script_size = 0;
    script = file ? read_stream(file, &script_size) : NULL;
    if (file) {
        fclose(file);
    }
    if (!script) {
        fprintf(stderr, "cannot read %s: %s\n", argv[1], strerror(errno));
        goto cleanup;
    }
    size_t input_size = 0;
    input = isatty(0) ? calloc(1, 1) : read_stream(stdin, &input_size);
    if (!input) {
        fprintf(stderr, "cannot read stdin: %s\n", strerror(errno));
        goto cleanup;
    }

    size_t script_offset = 0, input_offset = 0, output_offset = 0, error_offset = 0;
    size_t reserved_bytes = 0;
    if (script_size == SIZE_MAX || reserve_buffer(&reserved_bytes, script_size + 1, &script_offset) ||
        reserve_buffer(&reserved_bytes, input_size, &input_offset) || reserve_buffer(&reserved_bytes, QUICKJS_OUTPUT_BYTES, &output_offset) ||
        reserve_buffer(&reserved_bytes, QUICKJS_ERROR_BYTES, &error_offset) || reserved_bytes > SIZE_MAX - QUICKJS_HEAP_BYTES) {
        fprintf(stderr, "script and stdin are too large for Capsule memory\n");
        goto cleanup;
    }

    skeleton = quickjs__open();
    if (!skeleton) {
        fprintf(stderr, "open failed\n");
        goto cleanup;
    }
    if (bpf_capsule_configure(&capsule, skeleton->obj,
            (struct bpf_capsule_config){
                .fiber_count = 1,
                .heap_bytes = reserved_bytes + QUICKJS_HEAP_BYTES,
                .reserved_bytes = reserved_bytes,
            }) ||
        bpf_object__load_skeleton(skeleton->skeleton) || bpf_capsule_initialize(&capsule)) {
        fprintf(stderr, "cannot configure/load Capsule QuickJS: %s\n", strerror(errno));
        goto cleanup;
    }

    volatile struct quickjs_bpf_ctrl* control = &skeleton->data_qctrl->qctrl;
    char* memory = bpf_capsule_memory_reserved_start(&capsule);
    control->script.address = memory + script_offset;
    control->script.capacity = script_size + 1;
    control->script.size = script_size;
    control->input.address = memory + input_offset;
    control->input.capacity = input_size;
    control->input.size = input_size;
    control->output.address = memory + output_offset;
    control->output.capacity = QUICKJS_OUTPUT_BYTES;
    control->error.address = memory + error_offset;
    control->error.capacity = QUICKJS_ERROR_BYTES;
    if (bpf_capsule_memcpy(&capsule, control->script.address, script, script_size + 1) ||
        (input_size && bpf_capsule_memcpy(&capsule, control->input.address, input, input_size))) {
        fprintf(stderr, "cannot stage script and stdin: %s\n", strerror(errno));
        goto cleanup;
    }

    int run_fd = bpf_program__fd(skeleton->progs.quickjs_run);
    int drain_fd = bpf_program__fd(skeleton->progs.quickjs_drain);
    if (run_fd < 0 || drain_fd < 0) {
        fprintf(stderr, "BPF object is missing a QuickJS program\n");
        goto cleanup;
    }
    struct bpf_test_run_opts options = {.sz = sizeof(options)};
    if (bpf_prog_test_run_opts(run_fd, &options)) {
        perror("run");
        goto cleanup;
    }
    unsigned long drains = 0;
    while (control->capsule.status == CAPSULE_PENDING) {
        if (drains == QUICKJS_MAX_DRAINS) {
            fprintf(stderr, "gave up after %lu drains: computation still pending\n", drains);
            goto cleanup;
        }
        if (bpf_prog_test_run_opts(drain_fd, &options)) {
            perror("drain");
            goto cleanup;
        }
        drains++;
    }
    if (control->capsule.status == CAPSULE_EXITED) {
        size_t error_size = control->error.size < control->error.capacity ? control->error.size : control->error.capacity;
        if (error_size) {
            fwrite(control->error.address, 1, error_size, stderr);
            fputc('\n', stderr);
        }
        if (control->capsule.code < 0) {
            fprintf(stderr, "capsule stopped: %s (%lld)\n", bpf_capsule_error_string(control->capsule.code), (long long)control->capsule.code);
            goto cleanup;
        }
        result = (int)control->capsule.code;
        goto cleanup;
    }
    if (control->capsule.status != CAPSULE_OK) {
        fprintf(stderr, "capsule status=%s\n", bpf_capsule_status_string(control->capsule.status));
        goto cleanup;
    }
    if (control->output.size > control->output.capacity) {
        fprintf(stderr, "QuickJS stdout requires %zu bytes; the buffer holds %zu\n", control->output.size, control->output.capacity);
        goto cleanup;
    }
    if (control->output.size) {
        fwrite(control->output.address, 1, control->output.size, stdout);
    }
    fprintf(stderr, "continuation drains: %lu\n", drains);
    result = 0;

cleanup:
    if (skeleton) {
        (void)bpf_capsule_release(&capsule);
        quickjs__destroy(skeleton);
    }
    free(input);
    free(script);
    return result;
}
