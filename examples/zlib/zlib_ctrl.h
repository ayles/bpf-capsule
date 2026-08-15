// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#pragma once

#include "bpf_capsule_abi.h"

struct zlib_bpf_ctrl {
    uint64_t input_address;
    uint64_t input_size;
    uint64_t output_address;
    uint64_t output_capacity;
    uint64_t workspace_address;
    uint64_t workspace_capacity;
    uint64_t status;
    uint64_t output_size;
    uint64_t adler;
    struct capsule_result capsule;
};
