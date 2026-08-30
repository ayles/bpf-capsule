// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#pragma once

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#include "lua_xdp_ctrl.h"

extern struct lua_xdp_ctrl lua_xdp_control;
extern const unsigned int lua_exchange_key;

struct lua_exchange_map {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, unsigned int);
    __type(value, struct lua_exchange);
};
extern struct lua_exchange_map lua_exchange_by_cpu;

void lua_initialize_states(void);
size_t lua_xdp_execute(size_t packet_size);
