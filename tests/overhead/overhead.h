// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#pragma once

#include "bpf_capsule_types.h"

#include <stdint.h>

enum {
    OVERHEAD_ARITHMETIC_TRIPS = 2000,
    OVERHEAD_RECURSION_DEPTH = 128,
    OVERHEAD_MEMORY_WORDS = 64,
};

struct overhead_node {
    uint32_t next;
    uint32_t padding;
    uint64_t value;
};

struct overhead_state {
    struct capsule_result capsule;
    uint64_t result;
    int64_t divisor;
    uint32_t trips;
    uint32_t recurse;
    uint64_t logical_words;
    uint64_t logical_nodes;
    uint64_t direct_words[OVERHEAD_MEMORY_WORDS];
    struct overhead_node direct_nodes[OVERHEAD_MEMORY_WORDS];
};
