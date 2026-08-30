// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#pragma once

#include "bpf_capsule_types.h"

struct rust_bpf_ctrl {
    uint64_t checksum;
    struct capsule_result capsule;
};
