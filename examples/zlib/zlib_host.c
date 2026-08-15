// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
// Host side of the in-kernel zlib demo: deflate locally, inflate in the
// kernel, and compare bytes, checksum and speed against the same scalar
// sources built natively and against the platform's optimized system zlib.
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <zlib.h>

#include "bpf_capsule_host.h"

#include "zlib_ctrl.h"

#include "zlib.skel.h"

// From the Z_PREFIX copy of the exact upstream scalar sources used by the BPF
// target.  Keep this declaration in the normal zlib namespace translation
// unit so the system library remains available as the platform-optimized
// comparison and compressor.
extern int z_uncompress(unsigned char* dest, unsigned long* dest_len, const unsigned char* source, unsigned long source_len);

#define MAX_DRAINS 2000000
#define ZLIB_WORKSPACE_BYTES (2u << 20)

// A single cold call made the 64 KiB scalar result vary by more than 4x
// between otherwise identical VM boots.  Warm every implementation once and
// average a small fixed sample.
#define REPEATS 7

// Run one entry and drain budget-driven continuations until the capsule
// reaches a terminal state. Returns zero only when the capsule reports
// CAPSULE_OK.
static int
run_to_completion(int run_fd, int drain_fd, struct bpf_test_run_opts* options, volatile const struct capsule_result* capsule, unsigned long* drains) {
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
        fprintf(stderr, "usage: zlib [BYTES]\n");
        return 1;
    }
    char* size_end = NULL;
    errno = 0;
    unsigned long n = argc > 1 ? strtoul(argv[1], &size_end, 0) : (2u << 20);
    if (!n || n > UINT_MAX || errno || (size_end && *size_end)) {
        fprintf(stderr, "BYTES must be an integer from 1 through %u\n", UINT_MAX);
        return 1;
    }

    int result = 1;
    struct zlib* skeleton = NULL;
    unsigned char* data = NULL;
    unsigned char* comp = NULL;
    unsigned char* ref = NULL;
    unsigned char* scalar = NULL;

    // Compressible but not trivial: runs of a pattern with an LCG sprinkle.
    data = malloc(n);
    if (!data) {
        fprintf(stderr, "cannot allocate %lu input bytes\n", n);
        goto cleanup;
    }
    unsigned int lcg = 12345;
    for (unsigned long i = 0; i < n; i++) {
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
    fprintf(stderr, "in: %lu bytes -> %lu compressed\n", n, (unsigned long)clen);

    // The whole heap is one host-reserved prefix carved into three buffers;
    // the in-kernel inflate works out of the staged workspace, not malloc.
    uint64_t input_offset = 0;
    uint64_t output_offset = (input_offset + clen + 15u) & ~15ull;
    uint64_t workspace_offset = (output_offset + n + 15u) & ~15ull;
    uint64_t heap_bytes = workspace_offset + ZLIB_WORKSPACE_BYTES;

    skeleton = zlib__open();
    if (!skeleton) {
        fprintf(stderr, "open failed\n");
        goto cleanup;
    }
    const struct bpf_capsule_config capsule_config = {
        .fiber_count = 1,
        .heap_bytes = heap_bytes,
        .reserved_bytes = heap_bytes,
    };
    if (bpf_capsule_configure(skeleton->obj, capsule_config) || bpf_object__load_skeleton(skeleton->skeleton) ||
        bpf_capsule_finish_initialization(skeleton->obj)) {
        fprintf(stderr, "load failed: %s\n", strerror(errno));
        goto cleanup;
    }
    struct bpf_object* obj = skeleton->obj;
    volatile struct zlib_bpf_ctrl* control = &skeleton->data_zctrl->zctrl;
    struct bpf_capsule_memory memory;
    if (bpf_capsule_memory(obj, &memory)) {
        fprintf(stderr, "cannot map Capsule memory\n");
        goto cleanup;
    }

    uint64_t input_address = bpf_capsule_memory_reserved_start(&memory) + input_offset;
    uint64_t output_address = bpf_capsule_memory_reserved_start(&memory) + output_offset;
    uint64_t workspace_address = bpf_capsule_memory_reserved_start(&memory) + workspace_offset;
    if (bpf_capsule_memory_write(&memory, input_address, comp, clen)) {
        fprintf(stderr, "cannot write zlib input: %s\n", strerror(errno));
        goto cleanup;
    }
    control->input_address = input_address;
    control->input_size = clen;
    control->output_address = output_address;
    control->output_capacity = n;
    control->workspace_address = workspace_address;
    control->workspace_capacity = ZLIB_WORKSPACE_BYTES;

    int drain_fd = bpf_program__fd(skeleton->progs.zlib_drain);
    int run_fd = bpf_program__fd(skeleton->progs.zlib_run);
    if (drain_fd < 0 || run_fd < 0) {
        fprintf(stderr, "BPF object is missing a zlib program\n");
        goto cleanup;
    }
    struct bpf_test_run_opts options = {.sz = sizeof(options)};
    unsigned long continuation_drains = 0;

    // Untimed warmup keeps dynamic linking, page faults and cold code from
    // dominating a sub-millisecond native inflate.
    if (run_to_completion(run_fd, drain_fd, &options, &control->capsule, &continuation_drains)) {
        goto cleanup;
    }

    // Kernel-side BPF runtime accounting: with stats enabled, run_time_ns
    // accumulates each program's real execution nanoseconds, so the delta
    // over the timed inflates is their in-kernel time — never syscall wall
    // time.
    int stats_fd = bpf_enable_stats(BPF_STATS_RUN_TIME);
    uint64_t kernel_before = program_run_time(run_fd) + program_run_time(drain_fd);
    for (unsigned long i = 0; i < REPEATS; i++) {
        if (run_to_completion(run_fd, drain_fd, &options, &control->capsule, &continuation_drains)) {
            goto cleanup;
        }
    }
    double kms = (program_run_time(run_fd) + program_run_time(drain_fd) - kernel_before) / 1e6 / REPEATS;
    if (stats_fd >= 0) {
        close(stats_fd);
    }

    ref = malloc(n);
    if (!ref) {
        fprintf(stderr, "cannot allocate %lu reference bytes\n", n);
        goto cleanup;
    }
    int kernel_output_ok = 0;
    if (control->output_size == n) {
        if (bpf_capsule_memory_read(&memory, ref, output_address, n)) {
            fprintf(stderr, "cannot read zlib output: %s\n", strerror(errno));
        } else {
            kernel_output_ok = memcmp(ref, data, n) == 0;
        }
    }

    uLongf reflen = n;
    int system_ret = uncompress(ref, &reflen, comp, clen);
    uint64_t t0 = thread_ns();
    for (unsigned long i = 0; i < REPEATS; i++) {
        reflen = n;
        system_ret = uncompress(ref, &reflen, comp, clen);
    }
    double hms = (thread_ns() - t0) / 1e6 / REPEATS;
    int system_ok = system_ret == Z_OK && reflen == n && memcmp(ref, data, n) == 0;

    scalar = malloc(n);
    if (!scalar) {
        fprintf(stderr, "cannot allocate %lu scalar-reference bytes\n", n);
        goto cleanup;
    }
    unsigned long scalar_len = n;
    int scalar_ret = z_uncompress(scalar, &scalar_len, comp, clen);
    t0 = thread_ns();
    for (unsigned long i = 0; i < REPEATS; i++) {
        scalar_len = n;
        scalar_ret = z_uncompress(scalar, &scalar_len, comp, clen);
    }
    double sms = (thread_ns() - t0) / 1e6 / REPEATS;
    int scalar_ok = scalar_ret == Z_OK && scalar_len == n && memcmp(scalar, data, n) == 0;

    if (stats_fd >= 0) {
        fprintf(
            stderr,
            "inflate time over %d runs: kernel %.2f ms, matched scalar %.2f ms (%.1fx), "
            "system zlib %.2f ms (%.1fx)\n",
            REPEATS, kms, sms, sms > 0 ? kms / sms : 0, hms, hms > 0 ? kms / hms : 0
        );
    } else {
        fprintf(stderr, "inflate time over %d runs: matched scalar %.2f ms, system zlib %.2f ms\n", REPEATS, sms, hms);
    }
    fprintf(stderr, "continuation drains: %lu\n", continuation_drains);

    // The workload is deterministic integer C, so kernel, matched scalar and
    // system zlib must agree byte for byte — any divergence is a bug, not
    // noise.
    uint64_t want = adler32(adler32(0, Z_NULL, 0), data, n);
    int pass = kernel_output_ok && scalar_ok && system_ok && control->status == (uint64_t)(int64_t)Z_STREAM_END && control->adler == want &&
        control->capsule.status == CAPSULE_OK;
    if (!pass) {
        fprintf(stderr, "matched scalar: ret=%d len=%lu %s\n", scalar_ret, scalar_len, scalar_ok ? "OK" : "MISMATCH");
        fprintf(stderr, "system zlib: ret=%d len=%lu %s\n", system_ret, (unsigned long)reflen, system_ok ? "OK" : "MISMATCH");
        fprintf(
            stderr, "kernel: status=%lld output=%llu adler=%llx (want len=%lu adler=%llx)\n", (long long)(int64_t)control->status,
            (unsigned long long)control->output_size, (unsigned long long)control->adler, n, (unsigned long long)want
        );
    }
    result = pass ? 0 : 1;

cleanup:
    free(scalar);
    free(ref);
    if (skeleton) {
        zlib__destroy(skeleton);
    }
    free(comp);
    free(data);
    return result;
}
