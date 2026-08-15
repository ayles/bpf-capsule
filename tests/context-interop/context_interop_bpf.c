// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#include "bpf_capsule.h"
#include "context_interop_test.h"

volatile struct context_interop_output context_interop_result SEC(".data.ctxinterop");
volatile struct context_interop_request context_interop_request SEC(".data.ctxrequest");
static unsigned char context_interop_buffer[CONTEXT_INTEROP_BYTES];

static uint64_t context_interop_checksum(void) {
    uint64_t checksum = CONTEXT_INTEROP_FNV_OFFSET;
    for (unsigned int index = 0; index < CONTEXT_INTEROP_BYTES; ++index) {
        checksum = (checksum ^ context_interop_buffer[index]) * CONTEXT_INTEROP_FNV_PRIME;
    }
    return checksum;
}

#if CONTEXT_INTEROP_YIELD

static uint64_t context_interop_body(void) {
    context_interop_request.destination = (uint64_t)(unsigned long)context_interop_buffer;
    context_interop_request.offset = 0;
    context_interop_request.length = CONTEXT_INTEROP_BYTES;
    capsule_yield();
    return context_interop_checksum();
}

static __attribute__((always_inline)) int context_interop_copy(struct xdp_md* context) {
    unsigned char* data = (unsigned char*)(long)context->data;
    unsigned char* data_end = (unsigned char*)(long)context->data_end;
    unsigned int offset = context_interop_request.offset;
    unsigned int length = context_interop_request.length;
    if (offset != 0 || length != CONTEXT_INTEROP_BYTES || data + offset + length > data_end) {
        return -1;
    }

    unsigned char* destination = capsule_memory_pointer(unsigned char, context_interop_request.destination);
    __builtin_memcpy(destination, data + offset, CONTEXT_INTEROP_BYTES);
    return 0;
}

SEC("xdp")
int context_interop_run(struct xdp_md* context) {
    context_interop_result.protocol_error = 0;
    context_interop_result.copied = 0;
    context_interop_result.capsule = capsule_call(&context_interop_result.checksum, context_interop_body);
    if (context_interop_result.capsule.status == CAPSULE_YIELD) {
        if (context_interop_copy(context)) {
            context_interop_result.protocol_error = 1;
            struct capsule_result reset = capsule_reset(context_interop_result.capsule.continuation);
            if (reset.status != CAPSULE_OK) {
                context_interop_result.capsule = reset;
            }
            return XDP_ABORTED;
        }
        context_interop_result.copied = CONTEXT_INTEROP_BYTES;
        context_interop_result.capsule = capsule_continue(&context_interop_result.checksum, context_interop_result.capsule.continuation);
    }
    if (context_interop_result.capsule.status == CAPSULE_PENDING) {
        struct capsule_result reset = capsule_reset(context_interop_result.capsule.continuation);
        if (reset.status != CAPSULE_OK) {
            context_interop_result.capsule = reset;
        }
        return XDP_ABORTED;
    }
    return context_interop_result.capsule.status == CAPSULE_OK ? XDP_PASS : XDP_ABORTED;
}

#else

volatile struct context_interop_scalar_output context_interop_scalar_output SEC(".data.ctxscalar");

static uint64_t context_interop_scalar_body(void) {
    uint64_t value = 0x123456789abcdef0ull;
    for (unsigned int index = 0; index < 64; ++index) {
        value = value * 33 + index;
    }
    return value;
}

SEC("syscall")
int context_interop_scalar_run(void) {
    context_interop_scalar_output.capsule = capsule_call(&context_interop_scalar_output.value, context_interop_scalar_body);
    return context_interop_scalar_output.capsule.status;
}

SEC("syscall")
int context_interop_scalar_drain(void) {
    context_interop_scalar_output.capsule = capsule_continue(&context_interop_scalar_output.value, context_interop_scalar_output.capsule.continuation);
    return context_interop_scalar_output.capsule.status;
}

static uint64_t context_interop_body(struct xdp_md* context) {
    unsigned char* data = (unsigned char*)(long)context->data;
    unsigned char* data_end = (unsigned char*)(long)context->data_end;
    if (data + CONTEXT_INTEROP_BYTES > data_end) {
        return 0;
    }
    __builtin_memcpy(context_interop_buffer, data, CONTEXT_INTEROP_BYTES);
    return context_interop_checksum();
}

SEC("xdp")
int context_interop_run(struct xdp_md* context) {
    context_interop_result.protocol_error = 0;
    context_interop_result.copied = CONTEXT_INTEROP_BYTES;
    context_interop_result.capsule = capsule_call(&context_interop_result.checksum, context_interop_body, context);
    if (context_interop_result.capsule.status == CAPSULE_PENDING) {
        struct capsule_result reset = capsule_reset(context_interop_result.capsule.continuation);
        if (reset.status != CAPSULE_OK) {
            context_interop_result.capsule = reset;
        }
        return XDP_ABORTED;
    }
    return context_interop_result.capsule.status == CAPSULE_OK ? XDP_PASS : XDP_ABORTED;
}

#endif

SEC("xdp")
int context_interop_baseline(struct xdp_md* context) {
    return (unsigned char*)(long)context->data < (unsigned char*)(long)context->data_end ? XDP_PASS : XDP_ABORTED;
}

char _license[] SEC("license") = "GPL";
