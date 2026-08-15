// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#pragma once

#include "bpf_capsule_abi.h"

struct libc_test_result {
    struct capsule_result capsule;
    unsigned long long failures;
    unsigned long long parsed_max;
    unsigned long long parsed_overflow;
    unsigned long long parsed_negative;
    long parsed_min;
    unsigned int overflow_errno;
    int truncated_length;
    int formatted_length;
    char truncated[5];
    char formatted[160];
};
