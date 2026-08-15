// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#pragma once

#include "bpf_capsule_abi.h"

#define WASM_ZLIB_GUEST_INPUT_CAPACITY (128u << 10)
#define WASM_ZLIB_GUEST_OUTPUT_CAPACITY (256u << 10)

enum wasm3_stage {
    WASM3_STAGE_NOT_STARTED = 0,
    WASM3_STAGE_ENVIRONMENT_READY = 1,
    WASM3_STAGE_RUNTIME_READY = 2,
    WASM3_STAGE_MODULE_READY = 3,
    WASM3_STAGE_INPUT_READY = 4,
    WASM3_STAGE_COMPLETE = 5,
};

struct wasm3_bpf_ctrl {
    uint64_t input_address;
    uint64_t input_size;
    uint64_t stage;
    uint64_t zlib_status;
    uint64_t zlib_output_size;
    uint64_t zlib_adler;
    struct capsule_result capsule;
};

struct wasm_zlib_control {
    uint64_t input_len;
    uint64_t status;
    uint64_t output_len;
    uint64_t adler;
};
