// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#pragma once

#include <stddef.h>

#include "bpf_capsule_types.h"

enum {
    WASM_ZLIB_GUEST_INPUT_CAPACITY = 128u << 10,
    WASM_ZLIB_GUEST_OUTPUT_CAPACITY = 256u << 10,
};

struct wasm3_bpf_ctrl {
    unsigned char* input;
    size_t input_size;
    unsigned char* output;
    size_t output_capacity;
    int zlib_status;
    size_t output_size;
    struct capsule_result capsule;
};

// Fixed layout of guest_zctrl in wasm32 linear memory.
struct wasm_zlib_control {
    uint64_t input_len;
    uint64_t status;
    uint64_t output_len;
    uint64_t adler;
};
