// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
// Script, batch stdin, stdout and error buffers in Capsule memory.
#pragma once

#include <stddef.h>

#include "bpf_capsule_types.h"

struct lua_buffer {
    char* address;
    size_t capacity;
    size_t size;
};

struct lua_runner_ctrl {
    struct lua_buffer script;
    struct lua_buffer input;
    struct lua_buffer output;
    struct lua_buffer error;
    struct capsule_result capsule;
};
