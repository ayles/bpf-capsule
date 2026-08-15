// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#pragma once

#include "bpf_capsule.h"

// Shared map ABI. Keep the direct BPF object, transformed object and host on
// this one definition: capsule_result deliberately is not two legacy u64s.
struct oh_control {
    uint64_t digest;
    struct capsule_result capsule;
    unsigned int accepted;
    unsigned int parsed;
};

struct rust_oh_control {
    uint64_t digest;
    struct capsule_result capsule;
};
