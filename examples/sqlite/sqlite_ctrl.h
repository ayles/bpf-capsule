// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
// SQL script, result rows and the error message in Capsule memory.
#pragma once

#include <stddef.h>

#include "bpf_capsule_types.h"

struct sqlite_buffer {
    char* address;
    size_t capacity;
    size_t size;
};

struct sqlite_bpf_ctrl {
    struct sqlite_buffer script;
    struct sqlite_buffer output;
    struct sqlite_buffer error;
    int sqlite_rc;
    struct capsule_result capsule;
};
