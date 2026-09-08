// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#pragma once

#include <stddef.h>
#include <stdint.h>

#include "bpf_capsule_types.h"

#define PYTHON_ERROR_CAPACITY 512u

struct python_ctrl {
    const void* stdlib_image;
    size_t stdlib_size;
    const char* script;
    char* output;
    size_t output_capacity;
    size_t output_size;
    int64_t realtime_offset_ns;
    uint32_t hash_seed;
    struct capsule_result execution;
    char error[PYTHON_ERROR_CAPACITY];
};
