// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
// Run one Lua file with batch stdin and direct Capsule-memory output.

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "bpf_capsule_host.h"

#include "lua_runner_ctrl.h"
#include "lua.skel.h"

enum {
    LUA_OUTPUT_BYTES = 1u << 20,
    LUA_ERROR_BYTES = 64u << 10,
    LUA_HEAP_BYTES = 16u << 20,
};

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

static char* read_stream(FILE* file, size_t* size) {
    size_t capacity = 64u << 10;
    size_t used = 0;
    char* data = malloc(capacity);
    if (!data) {
        return NULL;
    }
    for (;;) {
        if (used == capacity) {
            if (capacity > SIZE_MAX / 2) {
                free(data);
                errno = EOVERFLOW;
                return NULL;
            }
            capacity *= 2;
            char* grown = realloc(data, capacity);
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
            *size = used;
            return data;
        }
    }
}

int main(int argc, char** argv) {
    if (argc != 2) {
        fprintf(stderr, "usage: lua SCRIPT\n");
        return 2;
    }
    unsigned long max_drains = 0;
    if (read_max_drains(&max_drains)) {
        return 2;
    }

    int result = 1;
    char* script = NULL;
    char* input = NULL;
    struct lua_runner* skeleton = NULL;
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

    if (script_size >= UINT32_MAX || input_size >= UINT32_MAX) {
        fprintf(stderr, "script and stdin are too large for Capsule memory\n");
        goto cleanup;
    }

    skeleton = lua_runner__open();
    if (!skeleton) {
        fprintf(stderr, "open failed\n");
        goto cleanup;
    }
    if (bpf_capsule_configure(&capsule, skeleton->obj,
            (struct bpf_capsule_config){
                .fiber_count = 1,
                .heap_bytes = (uint64_t)script_size + input_size + LUA_OUTPUT_BYTES + LUA_ERROR_BYTES + LUA_HEAP_BYTES,
            }) ||
        bpf_object__load_skeleton(skeleton->skeleton) || bpf_capsule_initialize(&capsule)) {
        fprintf(stderr, "cannot configure/load Capsule Lua: %s\n", strerror(errno));
        goto cleanup;
    }

    volatile struct lua_runner_ctrl* control = &skeleton->data_lua_runner->lua_runner_control;
    control->script.address = bpf_capsule_malloc(&capsule, script_size);
    control->script.capacity = script_size;
    control->script.size = script_size;
    control->input.address = bpf_capsule_malloc(&capsule, input_size);
    control->input.capacity = input_size;
    control->input.size = input_size;
    control->output.address = bpf_capsule_malloc(&capsule, LUA_OUTPUT_BYTES);
    control->output.capacity = LUA_OUTPUT_BYTES;
    control->error.address = bpf_capsule_malloc(&capsule, LUA_ERROR_BYTES);
    control->error.capacity = LUA_ERROR_BYTES;
    if (!control->script.address || !control->input.address || !control->output.address || !control->error.address) {
        perror("allocate lua buffers");
        goto cleanup;
    }
    if (script_size) {
        memcpy(control->script.address, script, script_size);
    }
    if (input_size) {
        memcpy(control->input.address, input, input_size);
    }

    int run_fd = bpf_program__fd(skeleton->progs.lua_run);
    int drain_fd = bpf_program__fd(skeleton->progs.lua_drain);
    if (run_fd < 0 || drain_fd < 0) {
        fprintf(stderr, "BPF object is missing a Lua program\n");
        goto cleanup;
    }
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
        fprintf(stderr, "Lua stdout requires %zu bytes; the buffer holds %zu\n", control->output.size, control->output.capacity);
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
        lua_runner__destroy(skeleton);
    }
    free(input);
    free(script);
    return result;
}
