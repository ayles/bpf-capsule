// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#pragma once

#include "bpf_capsule_abi.h"

enum rust_stage {
    RUST_STAGE_STARTED = 1,
    RUST_STAGE_COMPLETE,
};

struct rust_bpf_ctrl {
    uint64_t status;
    uint64_t result;
    struct capsule_result capsule;
};
