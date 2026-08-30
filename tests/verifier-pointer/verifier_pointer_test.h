// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#pragma once

#include "bpf_capsule_types.h"

struct verifier_pointer_map_value {
    uint64_t value;
    uint64_t guard;
};

struct verifier_pointer_value {
    uint64_t previous;
    uint64_t observed;
    uint64_t guard;
    uint64_t context_scalar;
};

struct verifier_pointer_result {
    struct capsule_result capsule;
    struct verifier_pointer_value value;
};
