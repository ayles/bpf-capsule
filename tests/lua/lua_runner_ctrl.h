// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
// Control block shared between lua_bpf.c and its host. The script, batch
// stdin, stdout and error buffers are guest globals in Capsule memory;
// lua_prepare publishes each one as an {address, capacity, size} triple and
// the host moves bytes with bpf_capsule_memcpy.
#pragma once

#include "bpf_capsule_types.h"

struct lua_buffer {
    char* address;     // bpf -> host: Capsule memory
    uint64_t capacity; // bpf -> host: bytes reserved at that address
    uint64_t size;     // bytes in use; the comments below name the writer
};

struct lua_runner_ctrl {
    struct lua_buffer script;      // size: host -> bpf
    struct lua_buffer input;       // size: host -> bpf, fully staged stdin
    struct lua_buffer output;      // size: bpf -> host; > capacity = truncated
    struct lua_buffer error;       // size: bpf -> host, Lua error message
    struct capsule_result capsule; // bpf -> host: completion/continuation
};
