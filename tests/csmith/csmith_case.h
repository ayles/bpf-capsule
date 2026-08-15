// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#pragma once

#include "bpf_capsule_abi.h"

struct csmith_test_result {
    struct capsule_result capsule;
    uint64_t checksum;
};
