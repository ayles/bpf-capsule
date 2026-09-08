// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#pragma once

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#include "python_xdp_ctrl.h"

extern struct python_xdp_ctrl python_xdp_control;
extern const unsigned int python_exchange_key;

struct python_exchange_map {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, unsigned int);
    __type(value, struct python_xdp_exchange);
};
extern struct python_exchange_map python_exchange_by_cpu;

void python_initialize(void);
size_t python_execute_packet(size_t packet_size);
