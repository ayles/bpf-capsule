// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
// Native XDP boundary and maps. The larger stock-Lua adapter is compiled
// separately without local-variable debug info due a Clang 22 BPF crash.
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#include "bpf_capsule.h"

#include "lua_xdp_internal.h"

struct lua_xdp_ctrl lua_xdp_control SEC(".data.lua_xdp");
const unsigned int lua_exchange_key SEC(".rodata.luaexchange") = 0;
struct lua_exchange_map lua_exchange_by_cpu SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20);
} lua_xdp_events SEC(".maps");

static struct lua_xdp_result lua_xdp_dispatch_body(struct xdp_md* ctx) {
    unsigned char* data = (unsigned char*)(long)ctx->data;
    unsigned char* data_end = (unsigned char*)(long)ctx->data_end;
    unsigned long length = (unsigned long)(data_end - data);
    if (length > LUA_XDP_PACKET_CAPACITY) {
        length = LUA_XDP_PACKET_CAPACITY;
    }
    return lua_xdp_execute(length);
}

SEC("syscall")
int lua_xdp_initialize(void) {
    lua_xdp_control.initialization = capsule_call_void(lua_initialize_states);
    return lua_xdp_control.initialization.status;
}

SEC("syscall")
int lua_xdp_initialize_drain(void) {
    lua_xdp_control.initialization = capsule_continue_void(lua_xdp_control.initialization.continuation);
    return lua_xdp_control.initialization.status;
}

SEC("xdp")
int lua_xdp_test(struct xdp_md* ctx) {
    // Loaded only by the separate deterministic test host. The live example
    // disables this entry; packet_filter.lua is the test/benchmark policy.
    struct lua_exchange* exchange = bpf_map_lookup_elem(&lua_exchange_by_cpu, &lua_exchange_key);
    if (!exchange) {
        return XDP_ABORTED;
    }
    exchange->test.value = (struct lua_xdp_result){0};
    exchange->test.capsule = capsule_call(&exchange->test.value, lua_xdp_dispatch_body, ctx);
    if (exchange->test.capsule.status == CAPSULE_OK) {
        return exchange->test.value.decision ? XDP_PASS : XDP_DROP;
    }
    if (exchange->test.capsule.status == CAPSULE_PENDING) {
        struct capsule_result reset = capsule_reset(exchange->test.capsule.continuation);
        if (reset.status != CAPSULE_OK) {
            exchange->test.capsule = reset;
        }
    }
    return XDP_ABORTED;
}

SEC("xdp")
int lua_xdp_baseline(struct xdp_md* ctx) {
    // Loaded only by the separate benchmark host as its no-Capsule baseline.
    // The live example disables this entry.
    (void)ctx;
    return XDP_PASS;
}

SEC("xdp")
int lua_xdp_observe(struct xdp_md* ctx) {
    struct lua_xdp_result result;
    struct capsule_result capsule = capsule_call(&result, lua_xdp_dispatch_body, ctx);
    if (capsule.status == CAPSULE_OK) {
        struct lua_exchange* exchange = bpf_map_lookup_elem(&lua_exchange_by_cpu, &lua_exchange_key);
        if (exchange) {
            unsigned long length = result.output_size < LUA_XDP_OUTPUT_CAPACITY ? (unsigned long)result.output_size : LUA_XDP_OUTPUT_CAPACITY;
            if (length) {
                (void)bpf_ringbuf_output(&lua_xdp_events, exchange->output.bytes, length, 0);
            }
        }
    } else if (capsule.status == CAPSULE_EXITED) {
        struct lua_exchange* exchange = bpf_map_lookup_elem(&lua_exchange_by_cpu, &lua_exchange_key);
        if (exchange) {
            unsigned long length = exchange->error_size < LUA_XDP_OUTPUT_CAPACITY ? (unsigned long)exchange->error_size : LUA_XDP_OUTPUT_CAPACITY;
            if (length) {
                (void)bpf_ringbuf_output(&lua_xdp_events, exchange->error.bytes, length, 0);
            }
        }
    } else if (capsule.status == CAPSULE_PENDING) {
        struct capsule_result reset = capsule_reset(capsule.continuation);
        if (reset.status != CAPSULE_OK) {
            struct lua_exchange* exchange = bpf_map_lookup_elem(&lua_exchange_by_cpu, &lua_exchange_key);
            if (exchange) {
                exchange->test.capsule = reset;
            }
        }
    }
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
