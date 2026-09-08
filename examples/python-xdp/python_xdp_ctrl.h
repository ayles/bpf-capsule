// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#pragma once

#include <stddef.h>
#include <stdint.h>

#include "bpf_capsule_types.h"

#define PYTHON_XDP_OUTPUT_CAPACITY 512u
#define PYTHON_XDP_PACKET_CAPACITY (1u << 11)

struct python_xdp_ctrl {
    const void* stdlib_image;
    size_t stdlib_size;
    const char* script;
    int64_t realtime_offset_ns;
    uint32_t hash_seed;
    struct capsule_result initialization;
    unsigned int faulted;
    char error[PYTHON_XDP_OUTPUT_CAPACITY];
};

struct python_xdp_exchange {
    char output[PYTHON_XDP_OUTPUT_CAPACITY];
    char error[PYTHON_XDP_OUTPUT_CAPACITY];
    size_t error_size;
};
