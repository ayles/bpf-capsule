// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#pragma once

#include <stdint.h>

struct rehash_test_result {
    struct capsule_result capsule;
    uint64_t failures;
    unsigned int old_size;
    unsigned int new_size;
    unsigned int calls;
    unsigned int grew;
    unsigned int poison_calls;
};
