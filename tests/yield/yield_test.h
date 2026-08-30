// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#pragma once

#include <stdint.h>

#define YIELD_TEST_SENTINEL 0xfeedfacecafebeefull
#define YIELD_TEST_ROUNDS 8

struct yield_test_state {
    struct capsule_result result;
    struct capsule_result stale_result;
    uint64_t output;
    uint64_t request;
    uint64_t response;
    uint64_t stage;
    uint64_t first_continuation;
    uint64_t stale_continuation;
    struct capsule_result benchmark_result;
    uint64_t benchmark_output;
    unsigned char* stack_probe;
    uint64_t stack_probe_checksum;
};
