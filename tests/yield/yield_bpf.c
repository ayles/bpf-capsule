// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#include "bpf_capsule.h"
#include "yield_test.h"

volatile struct yield_test_state yield_test_output SEC(".data.yieldtest");

static uint64_t yield_test_body(uint64_t seed) {
    unsigned char stack_probe[32];
    for (unsigned int index = 0; index < sizeof(stack_probe); ++index) {
        stack_probe[index] = (unsigned char)(seed + index * 3u);
    }
    yield_test_output.stack_probe = stack_probe;
    yield_test_output.request = seed + 1;
    yield_test_output.stage = 1;
    capsule_yield();

    uint64_t first_response = yield_test_output.response;
    yield_test_output.request = first_response * 3;
    yield_test_output.stage = 2;
    capsule_yield();

    yield_test_output.stage = 3;
    uint64_t checksum = 0;
    for (unsigned int index = 0; index < sizeof(stack_probe); ++index) {
        checksum += (uint64_t)stack_probe[index] * (index + 1u);
    }
    yield_test_output.stack_probe_checksum = checksum;
    return yield_test_output.request + yield_test_output.response;
}

SEC("syscall")
int yield_test_start(void) {
    yield_test_output.output = YIELD_TEST_SENTINEL;
    yield_test_output.result = capsule_call(&yield_test_output.output, yield_test_body, 7ull);
    yield_test_output.first_continuation = yield_test_output.result.continuation;
    return 0;
}

SEC("syscall")
int yield_test_first_continue(void) {
    if (yield_test_output.result.status != CAPSULE_YIELD) {
        return -1;
    }
    yield_test_output.response = yield_test_output.request + 10;
    yield_test_output.result = capsule_continue(&yield_test_output.output, yield_test_output.result.continuation);
    return 0;
}

SEC("syscall")
int yield_test_second_continue(void) {
    if (yield_test_output.result.status != CAPSULE_YIELD) {
        return -1;
    }
    yield_test_output.response = yield_test_output.request + 20;
    yield_test_output.result = capsule_continue(&yield_test_output.output, yield_test_output.result.continuation);
    return 0;
}

SEC("syscall")
int yield_test_stale_continue(void) {
    yield_test_output.stale_result = capsule_continue(&yield_test_output.output, yield_test_output.stale_continuation);
    return 0;
}

SEC("syscall")
int yield_test_reset_current(void) {
    yield_test_output.stale_result = capsule_reset(yield_test_output.result.continuation);
    return 0;
}

static uint64_t yield_benchmark_body(void) {
    uint64_t sum = 0;
    for (unsigned int round = 0; round < YIELD_TEST_ROUNDS; ++round) {
        yield_test_output.request = round + 1;
        capsule_yield();
        sum += yield_test_output.response;
    }
    return sum;
}

static uint64_t yield_baseline_body(void) {
    uint64_t sum = 0;
    for (unsigned int round = 0; round < YIELD_TEST_ROUNDS; ++round) {
        yield_test_output.request = round + 1;
        yield_test_output.response = yield_test_output.request * 2;
        sum += yield_test_output.response;
    }
    return sum;
}

#define HANDLE_YIELD() \
    do { \
        if (yield_test_output.benchmark_result.status == CAPSULE_YIELD) { \
            yield_test_output.response = yield_test_output.request * 2; \
            yield_test_output.benchmark_result = capsule_continue(&yield_test_output.benchmark_output, yield_test_output.benchmark_result.continuation); \
        } \
    } while (0)

SEC("syscall")
int yield_benchmark_run(void) {
    yield_test_output.benchmark_result = capsule_call(&yield_test_output.benchmark_output, yield_benchmark_body);
    HANDLE_YIELD();
    HANDLE_YIELD();
    HANDLE_YIELD();
    HANDLE_YIELD();
    HANDLE_YIELD();
    HANDLE_YIELD();
    HANDLE_YIELD();
    HANDLE_YIELD();
    return 0;
}

SEC("syscall")
int yield_baseline_run(void) {
    yield_test_output.benchmark_result = capsule_call(&yield_test_output.benchmark_output, yield_baseline_body);
    return 0;
}

char _license[] SEC("license") = "GPL";
