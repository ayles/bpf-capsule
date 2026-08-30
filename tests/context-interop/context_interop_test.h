// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#pragma once

#include "bpf_capsule_types.h"

#define CONTEXT_INTEROP_BYTES 64
#define CONTEXT_INTEROP_FNV_OFFSET 0xcbf29ce484222325ull
#define CONTEXT_INTEROP_FNV_PRIME 0x100000001b3ull

struct context_interop_request {
    unsigned char* destination;
    unsigned int offset;
    unsigned int length;
};

struct context_interop_output {
    struct capsule_result capsule;
    uint64_t checksum;
    unsigned int protocol_error;
    unsigned int copied;
};

struct context_interop_scalar_output {
    struct capsule_result capsule;
    uint64_t value;
};
