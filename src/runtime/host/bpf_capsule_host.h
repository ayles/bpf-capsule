// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception OR GPL-2.0-only
#pragma once

#include "bpf_capsule_types.h"
#include "internal/bpf_capsule_abi.h"

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

struct bpf_capsule_config {
    uint32_t fiber_count;
    uint64_t heap_bytes;
    uint64_t reserved_bytes;
};

// One host-side Capsule lifetime. Zero-initialize it, configure it before
// libbpf loads the object, initialize it after load, then release it before
// destroying the libbpf object. Release is safe after partial setup and safe
// to repeat.
struct bpf_capsule {
    struct bpf_object* object;
    void* private_data;
};

const char* bpf_capsule_status_string(uint32_t status);
const char* bpf_capsule_error_string(int64_t code);

int bpf_capsule_configure(struct bpf_capsule* capsule, struct bpf_object* object, struct bpf_capsule_config requested);
int bpf_capsule_initialize(struct bpf_capsule* capsule);
// Attach the freplace steps embedded in the original ELF after loading its
// base programs and before bpf_capsule_initialize().
int bpf_capsule_attach_freplace(struct bpf_capsule* capsule, const void* object_data, size_t object_size);
int bpf_capsule_release(struct bpf_capsule* capsule);

// Checked copies across a Capsule boundary. The Capsule side is inferred from
// the pointers; writes also maintain the fixed backend's boundary shadows.
int bpf_capsule_memcpy(const struct bpf_capsule* capsule, void* destination, const void* source, size_t size);
const void* bpf_capsule_memory_start(const struct bpf_capsule* capsule);
uint64_t bpf_capsule_memory_size(const struct bpf_capsule* capsule);
void* bpf_capsule_memory_reserved_start(const struct bpf_capsule* capsule);
uint64_t bpf_capsule_memory_reserved_size(const struct bpf_capsule* capsule);

#ifdef __cplusplus
}
#endif
