// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#pragma once

#include "bpf_capsule_types.h"

// Private in/out context for the allocator's syscall program. Each test-run
// invocation owns its context; no shared request map or host lock is needed.
enum __bpf_capsule_alloc_operation {
    BPF_CAPSULE_ALLOC_MALLOC,
    BPF_CAPSULE_ALLOC_FREE,
    BPF_CAPSULE_ALLOC_CONTINUE,
    BPF_CAPSULE_ALLOC_RESET,
};

struct __bpf_capsule_alloc_output {
    void* pointer;
    int error;
};

struct __bpf_capsule_alloc_request {
    uint64_t operation;
    uint64_t size;
    void* pointer;
    struct capsule_result result;
    struct __bpf_capsule_alloc_output output;
};
