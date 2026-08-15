// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#pragma once

#include "bpf_capsule_abi.h"

struct fib_state {
    unsigned int input;
    unsigned int output;
    struct capsule_result result;
};
