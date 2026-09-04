// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#pragma once

#include "bpf_capsule_types.h"

#include <stdint.h>

enum { MEMCPY_MAX_BYTES = 64 * 1024 };

struct memcpy_state {
    struct capsule_result capsule;
    uint64_t result;
    uint32_t bytes;
};
