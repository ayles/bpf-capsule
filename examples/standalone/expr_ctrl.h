// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#pragma once

#include <stddef.h>

#include "bpf_capsule_types.h"

struct expr_bpf_ctrl {
    char* input;
    size_t input_size;
    int64_t value;
    size_t error_at;
    int parse_error;
    struct capsule_result capsule;
};
