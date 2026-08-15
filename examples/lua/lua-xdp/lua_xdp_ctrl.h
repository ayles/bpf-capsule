// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#pragma once

#include "bpf_capsule_abi.h"

#define LUA_XDP_OUTPUT_CAPACITY 512u
#define LUA_XDP_SCRIPT_CAPACITY (1u << 20)
#define LUA_XDP_PACKET_CAPACITY (1u << 11)

struct lua_xdp_ctrl {
    uint64_t script_address;
    uint64_t script_size;
    uint64_t script_revision;
    struct capsule_result initialization;
};

struct lua_xdp_result {
    uint64_t output_size;
    uint64_t decision;
    uint64_t state_initializations;
};

struct lua_xdp_output_buffer {
    char bytes[LUA_XDP_OUTPUT_CAPACITY];
};

struct lua_xdp_test_result {
    struct capsule_result capsule;
    struct lua_xdp_result value;
};

// One native helper-compatible mailbox per CPU. Lua VM ownership and all
// persistent interpreter state are per Capsule fiber in unified memory.
struct lua_exchange {
    struct lua_xdp_output_buffer output;
    struct lua_xdp_output_buffer error;
    struct lua_xdp_test_result test;
    uint64_t error_size;
};
