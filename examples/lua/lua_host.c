// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
// Run one Lua file with batch stdin and direct Capsule-memory output, or the
// same runner natively with --native, reporting the execution time of both.

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "bpf_capsule_host.h"

#include "lua_runner.h"
#include "lua.skel.h"

enum {
    LUA_OUTPUT_BYTES = 1u << 20,
    LUA_ERROR_BYTES = 64u << 10,
    LUA_HEAP_BYTES = 16u << 20,
};

// The number of continuations a run may use; unlimited unless the environment
// caps it, so a regression in the drive budget can be turned into a failure.
// The kernel's own per-program counters, summed over the object: a wall clock
// around the syscall would also count the syscall path and this loop, which
// the native run does not pay. Run-time statistics must be enabled first.
static int kernel_run_time(struct bpf_object* object, uint64_t* nanoseconds, uint64_t* invocations) {
    uint64_t total_nanoseconds = 0;
    uint64_t total_invocations = 0;
    struct bpf_program* program;
    bpf_object__for_each_program(program, object) {
        int fd = bpf_program__fd(program);
        if (fd < 0) {
            continue;
        }
        struct bpf_prog_info info = {0};
        unsigned int length = sizeof(info);
        if (bpf_prog_get_info_by_fd(fd, &info, &length)) {
            return -1;
        }
        total_nanoseconds += info.run_time_ns;
        total_invocations += info.run_cnt;
    }
    *nanoseconds = total_nanoseconds;
    *invocations = total_invocations;
    return 0;
}

static int read_max_drains(unsigned long* result) {
    const char* text = getenv("BPF_CAPSULE_MAX_DRAINS");
    *result = ULONG_MAX;
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

static double milliseconds_since(const struct timespec* start, clockid_t clock) {
    struct timespec now;
    clock_gettime(clock, &now);
    return (double)(now.tv_sec - start->tv_sec) * 1e3 + (double)(now.tv_nsec - start->tv_nsec) / 1e6;
}

// Report the script's stdout, or its error and Lua's exit status.
static int publish(const struct lua_buffer* output, const struct lua_buffer* error, int failed, const char* engine) {
    if (failed) {
        size_t error_size = error->size < error->capacity ? error->size : error->capacity;
        if (error_size) {
            fwrite(error->address, 1, error_size, stderr);
            fputc('\n', stderr);
        }
        return 1;
    }
    if (output->size > output->capacity) {
        fprintf(stderr, "Lua stdout requires %zu bytes; the %s buffer holds %zu\n", output->size, engine, output->capacity);
        return 1;
    }
    if (output->size) {
        fwrite(output->address, 1, output->size, stdout);
    }
    return 0;
}

static int run_native(char* script, size_t script_size, char* input, size_t input_size) {
    struct lua_buffer script_buffer = {script, script_size, script_size};
    struct lua_buffer input_buffer = {input, input_size, input_size};
    struct lua_buffer output = {malloc(LUA_OUTPUT_BYTES), LUA_OUTPUT_BYTES, 0};
    struct lua_buffer error = {malloc(LUA_ERROR_BYTES), LUA_ERROR_BYTES, 0};
    if (!output.address || !error.address) {
        perror("allocate lua buffers");
        free(output.address);
        free(error.address);
        return 1;
    }
    struct timespec start;
    clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &start);
    int failed = lua_runner_run(&script_buffer, &input_buffer, &output, &error);
    double cpu_ms = milliseconds_since(&start, CLOCK_PROCESS_CPUTIME_ID);
    int result = publish(&output, &error, failed, "native");
    if (!failed) {
        fprintf(stderr, "native execution: %.3f ms\n", cpu_ms);
    }
    free(output.address);
    free(error.address);
    return result;
}

static int run_capsule(char* script, size_t script_size, char* input, size_t input_size, unsigned long max_drains) {
    if (script_size >= UINT32_MAX || input_size >= UINT32_MAX) {
        fprintf(stderr, "script and stdin are too large for Capsule memory\n");
        return 1;
    }
    int result = 1;
    int stats_fd = -1;
    struct lua_runner* skeleton = lua_runner__open();
    struct bpf_capsule capsule = {0};
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
    stats_fd = bpf_enable_stats(BPF_STATS_RUN_TIME);

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
    uint64_t kernel_before = 0, invocations_before = 0;
    int stats_failed = stats_fd < 0 || kernel_run_time(skeleton->obj, &kernel_before, &invocations_before);
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
    uint64_t kernel_after = 0, invocations_after = 0;
    stats_failed = stats_failed || kernel_run_time(skeleton->obj, &kernel_after, &invocations_after);
    if (control->capsule.status == CAPSULE_EXITED && control->capsule.code < 0) {
        fprintf(stderr, "capsule stopped: %s (%lld)\n", bpf_capsule_error_string(control->capsule.code), (long long)control->capsule.code);
        goto cleanup;
    }
    if (control->capsule.status != CAPSULE_OK && control->capsule.status != CAPSULE_EXITED) {
        fprintf(stderr, "capsule status=%s\n", bpf_capsule_status_string(control->capsule.status));
        goto cleanup;
    }
    struct lua_buffer output = {control->output.address, control->output.capacity, control->output.size};
    struct lua_buffer error = {control->error.address, control->error.capacity, control->error.size};
    int failed = control->capsule.status == CAPSULE_EXITED;
    result = publish(&output, &error, failed, "Capsule");
    if (failed) {
        result = (int)control->capsule.code;
        goto cleanup;
    }
    if (!stats_failed) {
        fprintf(stderr, "kernel execution: %.3f ms over %llu invocations\n", (double)(kernel_after - kernel_before) / 1e6,
            (unsigned long long)(invocations_after - invocations_before));
    }
    fprintf(stderr, "continuation drains: %lu\n", drains);

cleanup:
    if (stats_fd >= 0) {
        close(stats_fd);
    }
    if (skeleton) {
        (void)bpf_capsule_release(&capsule);
        lua_runner__destroy(skeleton);
    }
    return result;
}

int main(int argc, char** argv) {
    int native = argc >= 2 && !strcmp(argv[1], "--native");
    if (argc != 2 + native) {
        fprintf(stderr, "usage: lua [--native] SCRIPT\n");
        return 2;
    }
    unsigned long max_drains = 0;
    if (read_max_drains(&max_drains)) {
        return 2;
    }
    const char* path = argv[1 + native];

    int result = 1;
    char* script = NULL;
    char* input = NULL;
    FILE* file = fopen(path, "rb");
    size_t script_size = 0;
    script = file ? read_stream(file, &script_size) : NULL;
    if (file) {
        fclose(file);
    }
    if (!script) {
        fprintf(stderr, "cannot read %s: %s\n", path, strerror(errno));
        goto cleanup;
    }
    size_t input_size = 0;
    input = isatty(0) ? calloc(1, 1) : read_stream(stdin, &input_size);
    if (!input) {
        fprintf(stderr, "cannot read stdin: %s\n", strerror(errno));
        goto cleanup;
    }
    result = native ? run_native(script, script_size, input, input_size) : run_capsule(script, script_size, input, input_size, max_drains);

cleanup:
    free(input);
    free(script);
    return result;
}
