// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#pragma once

#include "bpf_capsule_types.h"

enum { ALLOCATOR_TEST_BYTES = 256 };

struct allocator_test_request {
    void* pointer;
    struct capsule_result result;
};
