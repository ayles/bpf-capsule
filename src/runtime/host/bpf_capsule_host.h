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

// After initialization, allocate through the guest's malloc/free using
// BPF_PROG_TEST_RUN. Each call leases an ordinary fiber and drives it to
// completion, then releases it.
// Concurrent calls are safe with the default allocator: requests do not share
// host state or a mutex. Supply enough fibers or synchronize calls yourself;
// EAGAIN means the pool was full and the operation did not start (including
// free). ENOMEM means malloc could not allocate; other failures set errno.
// Only EAGAIN guarantees the request did not start: do not blindly retry a
// free after another error. Destroying the Capsule reclaims all its blocks.
// malloc(0) requests one byte; free(NULL) succeeds without taking a fiber.
// Pointers can be passed between host and guest and freed on either side.
// As with free(), the pointer must be a live allocation from this Capsule.
// Configure/initialize/release must not race these calls or guest execution.
void* bpf_capsule_malloc(const struct bpf_capsule* capsule, size_t size);
int bpf_capsule_free(const struct bpf_capsule* capsule, void* pointer);

// After initialization, Capsule pointers can be read and written directly on
// either memory tier. Synchronize access to data shared with running BPF code.
void* bpf_capsule_memory_start(const struct bpf_capsule* capsule);
uint64_t bpf_capsule_memory_size(const struct bpf_capsule* capsule);

#ifdef __cplusplus
}
#endif
