// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#include <bpf/libbpf.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "bpf_capsule_host.h"

#include "../support/capsule_test.h"
#include "context_interop_test.h"

enum {
    SAMPLE_COUNT = 21,
    POLICY_REPEAT = 10000,
    BASELINE_REPEAT = 100000,
};

struct measurement {
    unsigned int policy_ns;
    unsigned int baseline_ns;
    unsigned int net_ns;
    uint64_t checksum;
};

static int compare_unsigned(const void* left, const void* right) {
    unsigned int a = *(const unsigned int*)left;
    unsigned int b = *(const unsigned int*)right;
    return (a > b) - (a < b);
}

static uint64_t expected_checksum(const unsigned char* packet) {
    uint64_t checksum = CONTEXT_INTEROP_FNV_OFFSET;
    for (unsigned int index = 0; index < CONTEXT_INTEROP_BYTES; ++index) {
        checksum = (checksum ^ packet[index]) * CONTEXT_INTEROP_FNV_PRIME;
    }
    return checksum;
}

static uint64_t expected_scalar(void) {
    uint64_t value = 0x123456789abcdef0ull;
    for (unsigned int index = 0; index < 64; ++index) {
        value = value * 33 + index;
    }
    return value;
}

static int measure_program(int fd, const unsigned char* packet, unsigned int repeat, unsigned int* duration, unsigned int* action) {
    unsigned char output[CONTEXT_INTEROP_BYTES] = {0};
    struct bpf_test_run_opts options = {
        .sz = sizeof(options),
        .data_in = packet,
        .data_size_in = CONTEXT_INTEROP_BYTES,
        .data_out = output,
        .data_size_out = sizeof(output),
        .repeat = repeat,
    };
    if (bpf_prog_test_run_opts(fd, &options)) {
        return -1;
    }
    *duration = options.duration;
    *action = options.retval;
    return 0;
}

static int measure_object(const char* path, const unsigned char* packet, struct measurement* measurement, int mixed_roots) {
    struct bpf_object* object = bpf_object__open_file(path, NULL);
    if (!object || capsule_test_load_object(object) || bpf_capsule_finish_initialization(object)) {
        bpf_object__close(object);
        return -1;
    }

    struct bpf_program* policy = bpf_object__find_program_by_name(object, "context_interop_run");
    struct bpf_program* baseline = bpf_object__find_program_by_name(object, "context_interop_baseline");
    struct bpf_map* output_map = bpf_object__find_map_by_name(object, ".data.ctxinterop");
    size_t output_size = 0;
    volatile struct context_interop_output* output = output_map ? bpf_map__initial_value(output_map, &output_size) : NULL;
    if (!policy || !baseline || !output || output_size < sizeof(*output)) {
        bpf_object__close(object);
        return -1;
    }

    if (mixed_roots) {
        size_t scalar_size = 0;
        volatile struct context_interop_scalar_output* scalar = capsule_test_global(object, "context_interop_scalar_output", &scalar_size);
        struct bpf_program* scalar_run = bpf_object__find_program_by_name(object, "context_interop_scalar_run");
        struct bpf_program* scalar_drain = bpf_object__find_program_by_name(object, "context_interop_scalar_drain");
        struct bpf_test_run_opts scalar_options = {.sz = sizeof(scalar_options)};
        if (!scalar || scalar_size < sizeof(*scalar) || !scalar_run || !scalar_drain) {
            fprintf(stderr, "mixed scalar/context interface is missing\n");
            bpf_object__close(object);
            return -1;
        }
        int scalar_error = capsule_test_drive(bpf_program__fd(scalar_run), bpf_program__fd(scalar_drain), &scalar_options, 1000, NULL, NULL, &scalar->capsule);
        if (scalar_error || scalar->capsule.status != CAPSULE_OK || scalar->capsule.code || scalar->value != expected_scalar()) {
            const char* reason = scalar_error ? strerror(errno) : "result mismatch";
            fprintf(
                stderr, "mixed scalar/context dispatch failed: %s; capsule status=%s code=%s (%lld)\n", reason,
                bpf_capsule_status_string(scalar->capsule.status), bpf_capsule_error_string(scalar->capsule.code), (long long)scalar->capsule.code
            );
            bpf_object__close(object);
            return -1;
        }
    }

    unsigned int duration = 0;
    unsigned int action = 0;
    if (measure_program(bpf_program__fd(policy), packet, 1, &duration, &action) || action != XDP_PASS || output->capsule.status != CAPSULE_OK ||
        output->capsule.code || output->protocol_error || output->copied != CONTEXT_INTEROP_BYTES || output->checksum != expected_checksum(packet)) {
        fprintf(
            stderr, "context interop failed: action=%u status=%u code=%lld protocol=%u copied=%u checksum=%llx/%llx\n", action, output->capsule.status,
            (long long)output->capsule.code, output->protocol_error, output->copied, output->checksum, expected_checksum(packet)
        );
        bpf_object__close(object);
        return -1;
    }

    unsigned int policy_samples[SAMPLE_COUNT];
    unsigned int baseline_samples[SAMPLE_COUNT];
    for (unsigned int sample = 0; sample < SAMPLE_COUNT; ++sample) {
        if (measure_program(bpf_program__fd(policy), packet, POLICY_REPEAT, &policy_samples[sample], &action) || action != XDP_PASS ||
            measure_program(bpf_program__fd(baseline), packet, BASELINE_REPEAT, &baseline_samples[sample], &action) || action != XDP_PASS) {
            bpf_object__close(object);
            return -1;
        }
    }
    qsort(policy_samples, SAMPLE_COUNT, sizeof(*policy_samples), compare_unsigned);
    qsort(baseline_samples, SAMPLE_COUNT, sizeof(*baseline_samples), compare_unsigned);
    measurement->policy_ns = policy_samples[SAMPLE_COUNT / 2];
    measurement->baseline_ns = baseline_samples[SAMPLE_COUNT / 2];
    measurement->net_ns = measurement->policy_ns > measurement->baseline_ns ? measurement->policy_ns - measurement->baseline_ns : 0;
    measurement->checksum = output->checksum;
    bpf_object__close(object);
    return 0;
}

int main(int argc, char** argv) {
    if (argc != 3) {
        fprintf(stderr, "usage: context_interop_test_host BORROWED_OBJECT YIELD_OBJECT\n");
        return 2;
    }

    unsigned char packet[CONTEXT_INTEROP_BYTES];
    for (unsigned int index = 0; index < sizeof(packet); ++index) {
        packet[index] = (unsigned char)(index * 37 + 11);
    }

    struct measurement borrowed = {0};
    struct measurement yielded = {0};
    int pass = !measure_object(argv[1], packet, &borrowed, 1) && !measure_object(argv[2], packet, &yielded, 0) && borrowed.checksum == yielded.checksum;
    double ratio = borrowed.net_ns ? (double)yielded.net_ns / borrowed.net_ns : 0.0;
    printf(
        "context interop: borrowed=%uns (%uns baseline, %uns net) yield=%uns (%uns baseline, %uns net) ratio=%.2fx\n", borrowed.policy_ns, borrowed.baseline_ns,
        borrowed.net_ns, yielded.policy_ns, yielded.baseline_ns, yielded.net_ns, ratio
    );
    printf(pass ? "CONTEXT-INTEROP-PASS\n" : "CONTEXT-INTEROP-FAIL\n");
    return pass ? 0 : 1;
}
