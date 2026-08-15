// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#pragma once

#include <stdint.h>

// Map ABI shared by the kernel fixture and its host assertions.
struct compiler_test_result {
    uint64_t failures;
    uint64_t checksum;
    uint64_t pending;
    int64_t code;
    int64_t sparse_pointer_difference;
    int64_t initialized_pointer_difference;
    uint64_t copy_failures;
    uint64_t first_copy_failure;
    uint64_t memset_failures;
    uint64_t first_memset_failure;
    uint64_t parallel_phi_sum;
    uint64_t native_atomic_failures;
};

struct compiler_guard_result {
    uint64_t intrinsic_status;
    int64_t intrinsic_code;
    uint64_t intrinsic_after;
    uint64_t intrinsic_value;
    uint64_t vla_before;
    uint64_t vla_after;
    unsigned int exit_held_status;
    unsigned int exit_status;
    int64_t exit_code;
    unsigned int exit_after;
    unsigned int exit_reuse_status;
    unsigned int exit_reset_status;
};

struct compiler_fiber_result {
    unsigned int start_status;
    unsigned int second_start_status;
    unsigned int other_status;
    int64_t other_code;
    unsigned int resume_status;
    int64_t resume_code;
    unsigned int exhausted_status;
    uint64_t first_fiber;
    uint64_t second_fiber;
    unsigned int reset_status;
    uint64_t reset_fiber;
    unsigned int after_reset_status;
    unsigned int after_reset_fiber;
    uint64_t paused_pending;
    int64_t paused_code;
    uint64_t other_value;
    uint64_t resumed_value;
};

struct compiler_allocator_result {
    struct capsule_result capsule[2];
    uint64_t first_fiber[2];
    uint64_t failures[2];
    uint64_t checksum[2];
    uint64_t operations[2];
};

struct compiler_return_value {
    uint64_t wide;
    unsigned int word;
    unsigned short half;
    unsigned char bytes[10];
};

struct compiler_return_result {
    struct capsule_result immediate_capsule;
    struct capsule_result suspended_capsule;
    struct compiler_return_value immediate;
    struct compiler_return_value suspended;
    unsigned int pending_output_unchanged;
};
