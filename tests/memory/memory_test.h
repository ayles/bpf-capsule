// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#pragma once

#include "bpf_capsule_abi.h"
#include "bpf_capsule_abi.h"

#define MEMORY_TEST_REGION_SIZE BPF_CAPSULE_MEMORY_REGION_SIZE
#define MEMORY_TEST_DIRECT_REGIONS BPF_CAPSULE_DIRECT_MEMORY_REGIONS
#define MEMORY_TEST_BYTES ((MEMORY_TEST_DIRECT_REGIONS + 1u) * MEMORY_TEST_REGION_SIZE + 64u)
#define MEMORY_TEST_PROBE_BYTES 64u

struct memory_test_result {
    struct capsule_result capsule;
    uint64_t address;
    uint64_t capacity;
    uint64_t probe_offset;
    uint64_t checksum;
};
