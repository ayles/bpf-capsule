// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#pragma once

#include <stddef.h>

#include "bpf_capsule_types.h"

#define LUA_XDP_OUTPUT_CAPACITY 512u
#define LUA_XDP_PACKET_CAPACITY (1u << 11)

struct lua_xdp_ctrl {
    char* script;
    size_t script_size;
    struct capsule_result initialization;
};

// One native helper-compatible mailbox per CPU. Lua VM ownership and all
// persistent interpreter state are per Capsule fiber in unified memory.
struct lua_exchange {
    char output[LUA_XDP_OUTPUT_CAPACITY];
    char error[LUA_XDP_OUTPUT_CAPACITY];
    size_t error_size;
};
