// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#pragma once

#include "bpf_capsule_abi.h"

enum llama2_stage {
    LLAMA2_STAGE_STARTED = 1,
    LLAMA2_STAGE_CONFIGURED,
    LLAMA2_STAGE_WEIGHTS_READY,
    LLAMA2_STAGE_STATE_READY,
    LLAMA2_STAGE_COMPLETE,
};

// Both scalar and quantized runners expose the same map ABI.
struct llama2_bpf_ctrl {
    uint64_t model_address; // host -> kernel: reserved Capsule memory
    uint64_t status;        // stage reached
    uint64_t steps;         // tokens generated
    uint64_t tok_sum;       // checksum over token IDs
    struct capsule_result capsule;
};
