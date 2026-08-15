// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
// Host side of the in-kernel wasm3 example: run the module in the kernel, run
// the identical module through a natively compiled wasm3, compare results.
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "bpf_capsule_host.h"

#include <zlib.h>

#include "wasm3.h"
#include "m3_env.h"
#include "wasm3_ctrl.h"

#include "wasm3.skel.h"

#include "zlib_wasm_module.h"

#define MAX_DRAINS 500000
#define WASM3_HEAP_BYTES (4ull << 20)

static void make_input(unsigned char* data, unsigned long size) {
    unsigned lcg = 12345;
    for (unsigned long i = 0; i < size; i++) {
        lcg = lcg * 1103515245u + 12345u;
        data[i] = (i & 0xfff) < 0xe00 ? (unsigned char)(i >> 6) : (unsigned char)(lcg >> 16);
    }
}

static int global_offset(IM3Module module, const char* name, uint32_t* offset) {
    IM3Global global = m3_FindGlobal(module, name);
    if (!global) {
        return 0;
    }
    M3TaggedValue value = {0};
    M3Result result = m3_GetGlobal(global, &value);
    if (result || value.type != c_m3Type_i32) {
        return 0;
    }
    *offset = value.value.i32;
    return 1;
}

static uint64_t program_run_time(int program_fd) {
    struct bpf_prog_info info = {};
    unsigned int info_length = sizeof(info);
    return bpf_prog_get_info_by_fd(program_fd, &info, &info_length) ? 0 : info.run_time_ns;
}

// Thread CPU time is the native analog of the kernel's run_time_ns.
static uint64_t thread_ns(void) {
    struct timespec time;
    clock_gettime(CLOCK_THREAD_CPUTIME_ID, &time);
    return (uint64_t)time.tv_sec * 1000000000ull + (uint64_t)time.tv_nsec;
}

int main(int argc, char** argv) {
    if (argc > 2) {
        fprintf(stderr, "usage: wasm3 [BYTES]\n");
        return 1;
    }
    char* size_end = NULL;
    errno = 0;
    unsigned long input_size = argc > 1 ? strtoul(argv[1], &size_end, 0) : 65536;
    if (!input_size || input_size > WASM_ZLIB_GUEST_OUTPUT_CAPACITY || errno || (size_end && *size_end)) {
        fprintf(stderr, "BYTES must be an integer from 1 through %u\n", WASM_ZLIB_GUEST_OUTPUT_CAPACITY);
        return 1;
    }

    int exit_code = 1;
    unsigned char* input = malloc(input_size);
    uLongf compressed_capacity = compressBound(input_size);
    unsigned char* compressed = malloc(compressed_capacity);
    unsigned char* native_output = malloc(input_size);
    struct wasm3* skeleton = NULL;
    IM3Environment env = NULL;
    IM3Runtime runtime = NULL;
    if (!input || !compressed || !native_output) {
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
        fprintf(stderr, "compressed wasm3 input exceeds the guest's %u-byte input buffer\n", WASM_ZLIB_GUEST_INPUT_CAPACITY);
        goto cleanup;
    }

    skeleton = wasm3__open();
    if (!skeleton) {
        fprintf(stderr, "open failed\n");
        goto cleanup;
    }
    struct bpf_object* obj = skeleton->obj;
    if (compressed_size > ULLONG_MAX - WASM3_HEAP_BYTES - 15u) {
        fprintf(stderr, "wasm3 heap size overflow\n");
        goto cleanup;
    }
    const struct bpf_capsule_config capsule_config = {
        .fiber_count = 1,
        .heap_bytes = WASM3_HEAP_BYTES + compressed_size + 15u,
        .reserved_bytes = compressed_size,
    };
    if (bpf_capsule_configure(obj, capsule_config) || bpf_object__load_skeleton(skeleton->skeleton) || bpf_capsule_finish_initialization(skeleton->obj)) {
        fprintf(stderr, "load failed: %s\n", strerror(errno));
        goto cleanup;
    }

    volatile struct wasm3_bpf_ctrl* control = &skeleton->data_w3ctrl->w3ctrl;
    struct bpf_capsule_memory capsule;
    if (bpf_capsule_memory(obj, &capsule)) {
        fprintf(stderr, "cannot map Capsule memory\n");
        goto cleanup;
    }
    uint64_t input_address = bpf_capsule_memory_reserved_start(&capsule);
    if (bpf_capsule_memory_write(&capsule, input_address, compressed, (size_t)compressed_size)) {
        fprintf(stderr, "cannot stage wasm3 input: %s\n", strerror(errno));
        goto cleanup;
    }
    control->input_address = input_address;
    control->input_size = compressed_size;

    int drain_fd = bpf_program__fd(skeleton->progs.wasm3_drain);
    int run_fd = bpf_program__fd(skeleton->progs.wasm3_zlib_run);
    if (drain_fd < 0 || run_fd < 0) {
        fprintf(stderr, "BPF object is missing a wasm3 program\n");
        goto cleanup;
    }
    struct bpf_test_run_opts options = {.sz = sizeof(options)};

    // Kernel-side BPF runtime accounting: with stats enabled, run_time_ns
    // accumulates each program's real execution nanoseconds — never syscall
    // wall time.
    int stats_fd = bpf_enable_stats(BPF_STATS_RUN_TIME);
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
    uint64_t kernel_ns = program_run_time(run_fd) + program_run_time(drain_fd);
    if (stats_fd >= 0) {
        close(stats_fd);
    }

    uint64_t t0 = thread_ns();
    env = m3_NewEnvironment();
    runtime = env ? m3_NewRuntime(env, 256 * 1024, NULL) : NULL;
    IM3Module module = NULL;
    M3Result result = !env ? "cannot create environment"
        : !runtime         ? "cannot create runtime"
                           : m3_ParseModule(env, &module, zlib_wasm_module, zlib_wasm_module_len);
    if (!result) {
        result = m3_LoadModule(runtime, module);
    }
    uint32_t input_offset = 0, output_offset = 0, control_offset = 0;
    if (!result &&
        (!global_offset(module, "guest_zin", &input_offset) || !global_offset(module, "guest_zout", &output_offset) ||
            !global_offset(module, "guest_zctrl", &control_offset))) {
        result = "missing guest globals";
    }
    uint32_t memory_size = 0;
    unsigned char* memory = result ? NULL : m3_GetMemory(runtime, &memory_size, 0);
    if (!result &&
        (!memory || input_offset > memory_size || compressed_size > memory_size - input_offset || output_offset > memory_size ||
            input_size > memory_size - output_offset || control_offset > memory_size || sizeof(struct wasm_zlib_control) > memory_size - control_offset)) {
        result = "guest memory too small";
    }
    if (!result) {
        memcpy(memory + input_offset, compressed, compressed_size);
        uint64_t guest_input_size = compressed_size;
        memcpy(memory + control_offset, &guest_input_size, sizeof(guest_input_size));
    }
    IM3Function function = NULL;
    if (!result) {
        result = m3_FindFunction(&function, runtime, "guest_zlib_run");
    }
    if (!result) {
        result = m3_CallArgv(function, 0, NULL);
    }
    struct wasm_zlib_control native_wasm = {0};
    int native_wasm_output_ok = 0;
    if (!result) {
        memcpy(&native_wasm, memory + control_offset, sizeof(native_wasm));
        native_wasm_output_ok = !memcmp(memory + output_offset, input, input_size);
    }
    uint64_t wasm_ns = thread_ns() - t0;
    if (result) {
        fprintf(stderr, "native wasm3 failed: %s\n", result);
        goto cleanup;
    }

    uLongf native_size = input_size;
    t0 = thread_ns();
    int zresult = uncompress(native_output, &native_size, compressed, compressed_size);
    uint64_t zlib_ns = thread_ns() - t0;
    unsigned long checksum = adler32(adler32(0, Z_NULL, 0), input, input_size);

    printf("stock zlib Wasm: %lu -> %lu compressed bytes, adler=%llx\n", input_size, (unsigned long)compressed_size, (unsigned long long)control->zlib_adler);
    if (stats_fd >= 0) {
        fprintf(
            stderr, "kernel wasm3 execution: %llu ns; native wasm3: %llu ns; native zlib: %llu ns\n", (unsigned long long)kernel_ns,
            (unsigned long long)wasm_ns, (unsigned long long)zlib_ns
        );
    } else {
        fprintf(stderr, "native wasm3: %llu ns; native zlib: %llu ns\n", (unsigned long long)wasm_ns, (unsigned long long)zlib_ns);
    }
    fprintf(stderr, "continuation drains: %lu\n", drains);

    int pass = control->stage == WASM3_STAGE_COMPLETE && control->capsule.status == CAPSULE_OK && control->zlib_status == Z_STREAM_END &&
        control->zlib_output_size == input_size && control->zlib_adler == checksum && native_wasm.status == Z_STREAM_END &&
        native_wasm.output_len == input_size && native_wasm.adler == checksum && native_wasm_output_ok && zresult == Z_OK && native_size == input_size &&
        !memcmp(native_output, input, input_size);
    if (!pass) {
        fprintf(
            stderr, "kernel and native disagree: kernel stage=%llu zstatus=%lld out=%llu adler=%llx, native wasm3 status=%lld out=%llu adler=%llx\n",
            (unsigned long long)control->stage, (long long)(int64_t)control->zlib_status, (unsigned long long)control->zlib_output_size,
            (unsigned long long)control->zlib_adler, (long long)(int64_t)native_wasm.status, (unsigned long long)native_wasm.output_len,
            (unsigned long long)native_wasm.adler
        );
    }
    exit_code = pass ? 0 : 1;

cleanup:
    if (runtime) {
        m3_FreeRuntime(runtime);
    }
    if (env) {
        m3_FreeEnvironment(env);
    }
    if (skeleton) {
        wasm3__destroy(skeleton);
    }
    free(native_output);
    free(compressed);
    free(input);
    return exit_code;
}
