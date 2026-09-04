// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#pragma once

#include "bpf_capsule_types.h"

struct smoke_state {
    struct capsule_result capsule;
    uint32_t input;
    uint32_t output;
};
