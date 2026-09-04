// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#pragma once

#include "bpf_capsule_types.h"

struct lua_buffer {
    char* address;
    uint64_t capacity;
    uint64_t size;
};

struct lua_runner_ctrl {
    struct lua_buffer script;
    struct lua_buffer input;
    struct lua_buffer output;
    struct lua_buffer error;
    struct capsule_result capsule;
};
