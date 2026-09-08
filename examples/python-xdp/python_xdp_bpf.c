// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
// Native XDP boundary and maps around the managed CPython interpreter.
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#include "bpf_capsule.h"
#include "python_xdp_internal.h"

struct python_xdp_ctrl python_xdp_control SEC(".data.python_xdp");
const unsigned int python_exchange_key SEC(".rodata.pythonexchange") = 0;
struct python_exchange_map python_exchange_by_cpu SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20);
} python_xdp_events SEC(".maps");

static size_t python_xdp_dispatch_body(void) {
    struct xdp_md* ctx = capsule_borrowed_ctx();
    unsigned char* data = (unsigned char*)(long)ctx->data;
    unsigned char* data_end = (unsigned char*)(long)ctx->data_end;
    size_t length = (size_t)(data_end - data);
    if (length > PYTHON_XDP_PACKET_CAPACITY) {
        length = PYTHON_XDP_PACKET_CAPACITY;
    }
    return python_execute_packet(length);
}

SEC("syscall")
int python_xdp_initialize(void) {
    python_xdp_control.initialization = capsule_call_void(python_initialize);
    return python_xdp_control.initialization.status;
}

SEC("syscall")
int python_xdp_initialize_drain(void) {
    python_xdp_control.initialization = capsule_continue_void(python_xdp_control.initialization.continuation);
    return python_xdp_control.initialization.status;
}

SEC("xdp")
int python_xdp_observe(struct xdp_md* ctx) {
    // This flag only disables observation; it publishes no interpreter data.
    if (__atomic_load_n(&python_xdp_control.faulted, __ATOMIC_RELAXED)) {
        return XDP_PASS;
    }
    struct python_xdp_exchange* mailbox = bpf_map_lookup_elem(&python_exchange_by_cpu, &python_exchange_key);
    if (!mailbox) {
        return XDP_PASS;
    }
    mailbox->error_size = 0;
    size_t output_size;
    struct capsule_result capsule = capsule_call_ctx(ctx, &output_size, python_xdp_dispatch_body);
    if (capsule.status == CAPSULE_OK) {
        struct python_xdp_exchange* exchange = bpf_map_lookup_elem(&python_exchange_by_cpu, &python_exchange_key);
        if (exchange) {
            unsigned long length = output_size < PYTHON_XDP_OUTPUT_CAPACITY ? (unsigned long)output_size : PYTHON_XDP_OUTPUT_CAPACITY;
            if (length) {
                (void)bpf_ringbuf_output(&python_xdp_events, exchange->output, length, 0);
            }
        }
    } else if (capsule.status == CAPSULE_EXITED && capsule.code != CAPSULE_ERROR_POOL_EXHAUSTED) {
        __atomic_store_n(&python_xdp_control.faulted, 1, __ATOMIC_RELAXED);
        struct python_xdp_exchange* exchange = bpf_map_lookup_elem(&python_exchange_by_cpu, &python_exchange_key);
        if (exchange) {
            unsigned long length = exchange->error_size < PYTHON_XDP_OUTPUT_CAPACITY ? (unsigned long)exchange->error_size : PYTHON_XDP_OUTPUT_CAPACITY;
            if (length) {
                (void)bpf_ringbuf_output(&python_xdp_events, exchange->error, length, 0);
            }
        }
    } else if (capsule.status == CAPSULE_PENDING || capsule.status == CAPSULE_YIELD) {
        static char message[] = "Python packet observer did not finish in one BPF invocation\n";
        __atomic_store_n(&python_xdp_control.faulted, 1, __ATOMIC_RELAXED);
        // Other CPython fibers may still reference a waiter on this stack.
        // Stop observing, but keep the continuation intact until teardown.
        (void)bpf_ringbuf_output(&python_xdp_events, message, sizeof(message) - 1, 0);
    }
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
