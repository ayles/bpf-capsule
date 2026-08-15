// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
// Run a script the way `lua SCRIPT < input` would: batch stdin in, script
// stdout out, Lua error text on stderr, script exit code back. The script
// executes inside the kernel through Capsule; --native runs the same script
// on the natively built Lua instead, so the two engines can be compared on
// any machine. Each run reports its real execution time: the kernel's own
// BPF runtime accounting (run_time_ns, never syscall wall time) or the
// native thread's CPU time.
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "bpf_capsule_host.h"
#include "lua.h"
#include "lauxlib.h"
#include "lualib.h"
#include "lua_runner_ctrl.h"
#include "lua.skel.h"

static char* read_stream(FILE* file, size_t* size) {
    size_t capacity = 64 << 10;
    size_t used = 0;
    char* data = malloc(capacity);
    while (data) {
        used += fread(data + used, 1, capacity - used, file);
        if (used < capacity) {
            break;
        }
        char* grown = realloc(data, capacity *= 2);
        if (!grown) {
            free(data);
        }
        data = grown;
    }
    if (!data || ferror(file)) {
        free(data);
        return NULL;
    }
    *size = used;
    return data;
}

// The same script through the natively built Lua, with the process's real
// stdin and stdout. Thread CPU time is the native analog of the kernel's
// run_time_ns.
static int run_native(const char* script, size_t script_size) {
    struct timespec begin;
    struct timespec end;
    lua_State* state = luaL_newstate();
    if (!state) {
        fprintf(stderr, "cannot create Lua state\n");
        return 1;
    }
    luaL_openlibs(state);
    clock_gettime(CLOCK_THREAD_CPUTIME_ID, &begin);
    int status = luaL_loadbuffer(state, script, script_size, "native.lua");
    if (status == LUA_OK) {
        status = lua_pcall(state, 0, 0, 0);
    }
    clock_gettime(CLOCK_THREAD_CPUTIME_ID, &end);
    if (status != LUA_OK) {
        fprintf(stderr, "%s\n", lua_tostring(state, -1));
    }
    lua_close(state);
    unsigned long long nanoseconds = (unsigned long long)(end.tv_sec - begin.tv_sec) * 1000000000ull + (unsigned long long)(end.tv_nsec - begin.tv_nsec);
    fprintf(stderr, "native execution: %llu ns\n", nanoseconds);
    return status == LUA_OK ? 0 : 1;
}

// The plain Capsule driving loop: enter once, then keep draining the
// continuation while the returned status is PENDING.
static int run_capsule(int entry_fd, int drain_fd, volatile struct lua_runner_ctrl* control, unsigned long* drains) {
    struct bpf_test_run_opts options = {.sz = sizeof(options)};
    if (bpf_prog_test_run_opts(entry_fd, &options)) {
        return -1;
    }
    while (control->capsule.status == CAPSULE_PENDING) {
        if (*drains == 2000000) {
            errno = ETIMEDOUT;
            return -1;
        }
        if (bpf_prog_test_run_opts(drain_fd, &options)) {
            return -1;
        }
        ++*drains;
    }
    return 0;
}

static uint64_t program_run_time(int program_fd) {
    struct bpf_prog_info info = {};
    unsigned int info_length = sizeof(info);
    return bpf_prog_get_info_by_fd(program_fd, &info, &info_length) ? 0 : info.run_time_ns;
}

static void report_capsule_failure(const char* operation, const volatile struct capsule_result* result) {
    if (result->status == CAPSULE_EXITED) {
        if (result->code < 0) {
            fprintf(stderr, "%s: %s (%lld)\n", operation, bpf_capsule_error_string(result->code), (long long)result->code);
        } else {
            fprintf(stderr, "%s: guest exited with code %lld\n", operation, (long long)result->code);
        }
        return;
    }
    fprintf(stderr, "%s: capsule status=%s\n", operation, bpf_capsule_status_string(result->status));
}

int main(int argc, char** argv) {
    int result = 1;
    int stats_fd = -1;
    struct lua_runner* skeleton = NULL;
    char* input = NULL;
    char* output = NULL;
    char* error_text = NULL;
    int native = argc > 1 && !strcmp(argv[1], "--native");
    if (argc != 2 + native) {
        fprintf(stderr, "usage: lua [--native] SCRIPT\n");
        return 2;
    }
    FILE* file = fopen(argv[1 + native], "rb");
    size_t script_size = 0;
    char* script = file ? read_stream(file, &script_size) : NULL;
    if (file) {
        fclose(file);
    }
    if (!script) {
        fprintf(stderr, "cannot read %s\n", argv[1 + native]);
        return 1;
    }
    if (native) {
        result = run_native(script, script_size);
        goto cleanup;
    }
    size_t input_size = 0;
    input = isatty(0) ? calloc(1, 1) : read_stream(stdin, &input_size);
    if (!input) {
        fprintf(stderr, "cannot read stdin\n");
        goto cleanup;
    }

    skeleton = lua_runner__open();
    const struct bpf_capsule_config config = {
        .fiber_count = 1,
        .heap_bytes = 16ull << 20,
    };
    if (!skeleton || bpf_capsule_configure(skeleton->obj, config) || bpf_object__load_skeleton(skeleton->skeleton) ||
        bpf_capsule_finish_initialization(skeleton->obj)) {
        fprintf(stderr, "cannot configure/load Capsule Lua: %s\n", strerror(errno));
        goto cleanup;
    }
    struct bpf_object* object = skeleton->obj;
    volatile struct lua_runner_ctrl* control = &skeleton->data_lua_runner->lua_runner_control;
    struct bpf_capsule_memory memory;
    if (bpf_capsule_memory(object, &memory)) {
        fprintf(stderr, "cannot map Capsule memory: %s\n", strerror(errno));
        goto cleanup;
    }

    unsigned long drains = 0;
    int prepare_fd = bpf_program__fd(skeleton->progs.lua_prepare);
    int run_fd = bpf_program__fd(skeleton->progs.lua_run);
    int drain_fd = bpf_program__fd(skeleton->progs.lua_drain);
    if (run_capsule(prepare_fd, drain_fd, control, &drains)) {
        fprintf(stderr, "cannot publish Lua buffers: %s\n", strerror(errno));
        goto cleanup;
    }
    if (control->capsule.status != CAPSULE_OK) {
        report_capsule_failure("cannot publish Lua buffers", &control->capsule);
        goto cleanup;
    }
    if (script_size > control->script.capacity || input_size > control->input.capacity) {
        fprintf(
            stderr, "script (%zu) or stdin (%zu) exceeds the guest buffers (%llu, %llu)\n", script_size, input_size,
            (unsigned long long)control->script.capacity, (unsigned long long)control->input.capacity
        );
        goto cleanup;
    }
    if (bpf_capsule_memory_write(&memory, control->script.address, script, script_size) ||
        (input_size && bpf_capsule_memory_write(&memory, control->input.address, input, input_size))) {
        fprintf(stderr, "cannot stage script and stdin: %s\n", strerror(errno));
        goto cleanup;
    }
    control->script.size = script_size;
    control->input.size = input_size;

    // Kernel-side BPF runtime accounting for the script run itself: staging
    // and buffer publication are already done, so run + drain nanoseconds
    // are the script's real in-kernel execution time.
    stats_fd = bpf_enable_stats(BPF_STATS_RUN_TIME);
    if (run_capsule(run_fd, drain_fd, control, &drains)) {
        fprintf(stderr, "Capsule Lua invocation failed: %s; capsule status=%s\n", strerror(errno), bpf_capsule_status_string(control->capsule.status));
        goto cleanup;
    }
    uint64_t kernel_ns = program_run_time(run_fd) + program_run_time(drain_fd);
    if (control->capsule.status == CAPSULE_EXITED) {
        size_t error_size = control->error.size < control->error.capacity ? control->error.size : control->error.capacity;
        error_text = malloc(error_size ? error_size : 1);
        if (error_size && error_text && !bpf_capsule_memory_read(&memory, error_text, control->error.address, error_size)) {
            fwrite(error_text, 1, error_size, stderr);
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
        fprintf(stderr, "Capsule Lua: capsule status=%s\n", bpf_capsule_status_string(control->capsule.status));
        goto cleanup;
    }
    if (control->output.size > control->output.capacity) {
        fprintf(
            stderr, "Lua stdout requires %llu bytes; the guest buffer holds %llu\n", (unsigned long long)control->output.size,
            (unsigned long long)control->output.capacity
        );
        goto cleanup;
    }
    size_t output_size = control->output.size;
    output = malloc(output_size ? output_size : 1);
    if (!output || bpf_capsule_memory_read(&memory, output, control->output.address, output_size)) {
        fprintf(stderr, "cannot read Capsule Lua output: %s\n", strerror(errno));
        goto cleanup;
    }
    fwrite(output, 1, output_size, stdout);
    if (stats_fd >= 0) {
        fprintf(stderr, "kernel execution: %llu ns\n", (unsigned long long)kernel_ns);
    }
    fprintf(stderr, "continuation drains: %lu\n", drains);
    result = 0;

cleanup:
    if (stats_fd >= 0) {
        close(stats_fd);
    }
    lua_runner__destroy(skeleton);
    free(error_text);
    free(output);
    free(input);
    free(script);
    return result;
}
