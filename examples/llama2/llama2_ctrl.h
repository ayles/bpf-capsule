// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#pragma once

#include <stddef.h>

#include "bpf_capsule_types.h"

enum { LLAMA2_MAX_TOKENS = 32 };

// Both floating-point and quantized runners expose the same result.
struct llama2_bpf_ctrl {
    const unsigned char* model;
    size_t model_size;
    unsigned int requested_tokens;
    unsigned int generated_tokens;
    int tokens[LLAMA2_MAX_TOKENS];
    struct capsule_result capsule;
};
