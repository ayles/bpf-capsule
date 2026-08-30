// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#pragma once

#include <stddef.h>

#include "bpf_capsule_types.h"

// inflate uses about 7 KiB of state and at most one 32 KiB window.
enum { ZLIB_WORKSPACE_BYTES = 64u << 10 };

struct zlib_bpf_ctrl {
    unsigned char* input;
    size_t input_size;
    unsigned char* output;
    size_t output_capacity;
    unsigned char* workspace;
    int status;
    size_t output_size;
    struct capsule_result capsule;
};
