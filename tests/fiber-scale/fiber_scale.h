// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#pragma once

#include <stdint.h>

#define FIBER_SCALE_COUNT 512u
#define FIBER_SCALE_LAST (FIBER_SCALE_COUNT - 1)
#define FIBER_SCALE_LOCAL_BYTES 128u
#define FIBER_SCALE_SEED 0x5au

struct fiber_scale_result {
    uint64_t checksum;
    uint64_t acquired_sum;
    unsigned int observed_fiber;
    unsigned int active_fibers;
    unsigned int call_status;
    unsigned int stack_cursor_zero;
    unsigned int acquire_attempts;
    unsigned int acquired;
    unsigned int acquire_failures;
    unsigned int exhausted;
    unsigned int release_attempts;
    unsigned int release_failures;
    unsigned int recycled;
};
