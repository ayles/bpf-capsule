// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
// Control block shared between quickjs_bpf.c and its host. The script, batch
// stdin, stdout and error buffers are guest globals in Capsule memory;
// quickjs_prepare publishes each one as an {address, capacity, size} triple
// and the host moves bytes with bpf_capsule_memory_write/read.
#pragma once

#include "bpf_capsule_abi.h"

struct qjs_buffer {
    uint64_t address;  // bpf -> host: capsule virtual address
    uint64_t capacity; // bpf -> host: bytes reserved at that address
    uint64_t size;     // bytes in use; the comments below name the writer
};

struct quickjs_bpf_ctrl {
    struct qjs_buffer script;      // size: host -> bpf, NUL kept past size
    struct qjs_buffer input;       // size: host -> bpf, fully staged stdin
    struct qjs_buffer output;      // size: bpf -> host; > capacity = truncated
    struct qjs_buffer error;       // size: bpf -> host, exception text
    struct capsule_result capsule; // bpf -> host: completion/continuation
};
