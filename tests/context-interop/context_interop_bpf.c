// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#include "bpf_capsule.h"
#include "context_interop_test.h"

volatile struct context_interop_output context_interop_result SEC(".data.ctxinterop");
static unsigned char context_interop_buffer[CONTEXT_INTEROP_BYTES];

static uint64_t context_interop_checksum(void) {
    uint64_t checksum = CONTEXT_INTEROP_FNV_OFFSET;
    for (unsigned int index = 0; index < CONTEXT_INTEROP_BYTES; ++index) {
        checksum = (checksum ^ context_interop_buffer[index]) * CONTEXT_INTEROP_FNV_PRIME;
    }
    return checksum;
}

static uint64_t context_interop_body(void) {
    struct xdp_md* context = capsule_borrowed_ctx();
#if CONTEXT_INTEROP_YIELD
    capsule_yield();
#endif
    unsigned char* data = (unsigned char*)(long)context->data;
    unsigned char* data_end = (unsigned char*)(long)context->data_end;
    if (data + CONTEXT_INTEROP_BYTES > data_end) {
        return 0;
    }
    __builtin_memcpy(context_interop_buffer, data, CONTEXT_INTEROP_BYTES);
    return context_interop_checksum();
}

#if !CONTEXT_INTEROP_YIELD
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
#endif

SEC("xdp")
int context_interop_run(struct xdp_md* context) {
    context_interop_result.protocol_error = 0;
    context_interop_result.copied = 0;
    context_interop_result.capsule = capsule_call_ctx(context, &context_interop_result.checksum, context_interop_body);
#if CONTEXT_INTEROP_YIELD
    if (context_interop_result.capsule.status == CAPSULE_YIELD) {
        context_interop_result.capsule = capsule_continue_ctx(context, &context_interop_result.checksum, context_interop_result.capsule.continuation);
    }
#endif
    if (context_interop_result.capsule.status == CAPSULE_PENDING) {
        struct capsule_result reset = capsule_reset(context_interop_result.capsule.continuation);
        if (reset.status != CAPSULE_OK) {
            context_interop_result.capsule = reset;
        }
        return XDP_ABORTED;
    }
    if (context_interop_result.capsule.status == CAPSULE_OK) {
        context_interop_result.copied = CONTEXT_INTEROP_BYTES;
    }
    return context_interop_result.capsule.status == CAPSULE_OK ? XDP_PASS : XDP_ABORTED;
}

// The same work through a void root: the checksum travels through the data
// section instead of an output slot, and the yield build resumes through
// capsule_continue_void_ctx.
volatile struct context_interop_output context_interop_void_result SEC(".data.ctxvoid");

static void context_interop_void_body(void) {
    context_interop_void_result.checksum = context_interop_body();
}

SEC("xdp")
int context_interop_void_run(struct xdp_md* context) {
    context_interop_void_result.protocol_error = 0;
    context_interop_void_result.copied = 0;
    context_interop_void_result.checksum = 0;
    context_interop_void_result.capsule = capsule_call_void_ctx(context, context_interop_void_body);
#if CONTEXT_INTEROP_YIELD
    if (context_interop_void_result.capsule.status == CAPSULE_YIELD) {
        context_interop_void_result.capsule = capsule_continue_void_ctx(context, context_interop_void_result.capsule.continuation);
    }
#endif
    if (context_interop_void_result.capsule.status == CAPSULE_PENDING) {
        struct capsule_result reset = capsule_reset(context_interop_void_result.capsule.continuation);
        if (reset.status != CAPSULE_OK) {
            context_interop_void_result.capsule = reset;
        }
        return XDP_ABORTED;
    }
    if (context_interop_void_result.capsule.status == CAPSULE_OK) {
        context_interop_void_result.copied = CONTEXT_INTEROP_BYTES;
    }
    return context_interop_void_result.capsule.status == CAPSULE_OK ? XDP_PASS : XDP_ABORTED;
}

SEC("xdp")
int context_interop_baseline(struct xdp_md* context) {
    return (unsigned char*)(long)context->data < (unsigned char*)(long)context->data_end ? XDP_PASS : XDP_ABORTED;
}

char _license[] SEC("license") = "GPL";
