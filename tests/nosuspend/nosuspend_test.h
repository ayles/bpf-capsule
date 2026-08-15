// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#pragma once

#include <stdint.h>

struct nosuspend_result {
    uint64_t value;
    int64_t code;
    unsigned int status;
};
