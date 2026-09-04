// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
// Shared by the guest and the host: the skeleton types the guest's data
// section, so the host translation unit must see the same definition.
#pragma once

#include "bpf_capsule_types.h"

struct smoke_result {
    int recursion;
    int many_args;
    int depth;
    int cpp;
    struct capsule_result capsule;
};
