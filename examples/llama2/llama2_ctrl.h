// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#pragma once

#include <stddef.h>

#include "bpf_capsule_types.h"

enum { LLAMA2_PROMPT_MAX = 512 };

// run.c's parameters after its argument parsing, plus the checkpoint and the
// tokenizer staged in Capsule memory and the buffer that receives the
// generated text. Both the floating-point and the quantized runner take the
// same block.
struct llama2_bpf_ctrl {
    const unsigned char* model;
    size_t model_size;
    const unsigned char* tokenizer;
    size_t tokenizer_size;
    char* output;
    size_t output_capacity;
    size_t output_size;
    float temperature;
    float topp;
    unsigned long long seed;
    int steps;
    unsigned char has_prompt;
    char prompt[LLAMA2_PROMPT_MAX];
    struct capsule_result capsule;
};
