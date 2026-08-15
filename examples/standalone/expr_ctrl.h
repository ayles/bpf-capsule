// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#pragma once

#include "bpf_capsule_abi.h"

// Shared map ABI. Keep this in one header: the host reads the exact bytes
// written by the BPF program.

// Stage codes reported through ectrl.status, so a failure says where it
// happened rather than only that it did.
enum expr_stage {
    EXPR_STAGE_ENTERED = 1,   // root reached, runtime initialized
    EXPR_STAGE_DONE = 2,      // evaluation finished, value is valid
    EXPR_ERROR_BAD_LEN = 100, // input size was zero
    EXPR_ERROR_PARSE = 101,   // evaluator rejected the input; see error_at
};

// The input buffer is a guest global in Capsule memory; expr_prepare
// publishes it as an {address, capacity, size} triple and the host stages
// bytes with bpf_capsule_memory_write.
struct expr_buffer {
    uint64_t address;  // kernel -> host: capsule virtual address
    uint64_t capacity; // kernel -> host: bytes reserved at that address
    uint64_t size;     // host -> kernel: input length in bytes
};

struct expr_bpf_ctrl {
    struct expr_buffer input;
    uint64_t status;               // kernel -> host: stage reached
    int64_t value;                 // kernel -> host: result, written by capsule_call
    uint64_t error_at;             // kernel -> host: first bad byte on parse error
    struct capsule_result capsule; // completion, continuation, or error
};
