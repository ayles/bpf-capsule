// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
// Native XDP boundary and maps. The larger stock-Lua adapter is compiled
// separately because full debug info for it crashes the BPF frontend.
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

static size_t lua_xdp_dispatch_body(struct xdp_md* ctx) {
    unsigned char* data = (unsigned char*)(long)ctx->data;
    unsigned char* data_end = (unsigned char*)(long)ctx->data_end;
    size_t length = (size_t)(data_end - data);
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
int lua_xdp_observe(struct xdp_md* ctx) {
    struct lua_exchange* mailbox = bpf_map_lookup_elem(&lua_exchange_by_cpu, &lua_exchange_key);
    if (!mailbox) {
        return XDP_PASS;
    }
    mailbox->error_size = 0;
    size_t output_size;
    struct capsule_result capsule = capsule_call(&output_size, lua_xdp_dispatch_body, ctx);
    if (capsule.status == CAPSULE_OK) {
        struct lua_exchange* exchange = bpf_map_lookup_elem(&lua_exchange_by_cpu, &lua_exchange_key);
        if (exchange) {
            unsigned long length = output_size < LUA_XDP_OUTPUT_CAPACITY ? (unsigned long)output_size : LUA_XDP_OUTPUT_CAPACITY;
            if (length) {
                (void)bpf_ringbuf_output(&lua_xdp_events, exchange->output, length, 0);
            }
        }
    } else if (capsule.status == CAPSULE_EXITED) {
        struct lua_exchange* exchange = bpf_map_lookup_elem(&lua_exchange_by_cpu, &lua_exchange_key);
        if (exchange) {
            unsigned long length = exchange->error_size < LUA_XDP_OUTPUT_CAPACITY ? (unsigned long)exchange->error_size : LUA_XDP_OUTPUT_CAPACITY;
            if (length) {
                (void)bpf_ringbuf_output(&lua_xdp_events, exchange->error, length, 0);
            }
        }
    } else if (capsule.status == CAPSULE_PENDING) {
        (void)capsule_reset(capsule.continuation);
    }
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
