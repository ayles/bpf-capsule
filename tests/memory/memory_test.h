// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#pragma once

#include "bpf_capsule_abi.h"

#define MEMORY_TEST_REGION_SIZE BPF_CAPSULE_MEMORY_REGION_SIZE
#define MEMORY_TEST_PROBE_BYTES 64u
#define MEMORY_TEST_NODE_OFFSET 12288u
#define MEMORY_TEST_NODE_COUNT 4u

struct alignment_control {
    struct capsule_result result;
    unsigned char* address;
    uint64_t value;
    uint64_t observed;
    uint32_t mode;
    uint32_t counter;
};

// Built by the guest in capsule heap memory and walked by the host through
// the stored pointers themselves: with the shared pointer representation
// (arena tier natively; fixed tier under a prepared view) `next` needs no
// translation on either side.
struct memory_test_node {
    struct memory_test_node* next;
    uint64_t value;
};

struct memory_test_result {
    struct capsule_result capsule;
    unsigned char* address;
    uint64_t capacity;
    uint64_t probe_offset;
    uint64_t checksum;
    struct memory_test_node* chain;
    uint32_t pointer_high;
};
