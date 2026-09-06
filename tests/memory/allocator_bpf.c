// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#include "bpf_capsule.h"
#include "allocator_test.h"

#include <stdlib.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

static void* exchange_body(void* pointer) {
    if (pointer) {
        unsigned char* bytes = pointer;
        for (unsigned i = 0; i < ALLOCATOR_TEST_BYTES; ++i) {
            if (bytes[i] != (unsigned char)i) {
                capsule_exit(1);
            }
        }
        free(pointer);
        return NULL;
    }
    unsigned char* bytes = malloc(ALLOCATOR_TEST_BYTES);
    if (!bytes) {
        capsule_exit(2);
    }
    for (unsigned i = 0; i < ALLOCATOR_TEST_BYTES; ++i) {
        bytes[i] = (unsigned char)i;
    }
    return bytes;
}

static void hold_body(void) {
    capsule_yield();
}

SEC("syscall")
int allocator_exchange(struct allocator_test_request* request) {
    void* output = NULL;
    request->result = capsule_call(&output, exchange_body, request->pointer);
    request->pointer = output;
    return 0;
}

SEC("syscall")
int allocator_hold(struct allocator_test_request* request) {
    request->result = capsule_call_void(hold_body);
    return 0;
}

SEC("syscall")
int allocator_reset(struct allocator_test_request* request) {
    request->result = capsule_reset(request->result.continuation);
    return 0;
}

char _license[] SEC("license") = "GPL";
