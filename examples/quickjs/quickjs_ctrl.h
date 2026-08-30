// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
// Script, batch stdin, stdout and exception buffers in Capsule memory.
#pragma once

#include <stddef.h>

#include "bpf_capsule_types.h"

struct qjs_buffer {
    char* address;
    size_t capacity;
    size_t size;
};

struct quickjs_bpf_ctrl {
    struct qjs_buffer script;
    struct qjs_buffer input;
    struct qjs_buffer output;
    struct qjs_buffer error;
    struct capsule_result capsule;
};
