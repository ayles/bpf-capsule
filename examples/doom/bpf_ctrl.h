// SPDX-License-Identifier: GPL-2.0-only
// Control block shared between the BPF program (doom_bpf.c) and its host.
// It lives in the mmapped .data.ctrl map, so both sides access it directly;
// the WAD and framebuffer themselves remain in Capsule memory.
#pragma once

#include "bpf_capsule_types.h"

// A terminal tick can release the previous key and press its replacement.
#define DOOM_INPUT_QUEUE_CAPACITY 2u
#define DOOM_INPUT_DOWN (1u << 31)
#define DOOM_INPUT_KEY_MASK 0xffffu

struct doom_bpf_ctrl {
    unsigned char* wad;               // host -> bpf: WAD in reserved Capsule memory
    uint64_t wad_size;                // host -> bpf: total WAD size
    const unsigned char* framebuffer; // bpf -> host: current 320x200 RGBA frame
    unsigned int start_in_e1m1;       // host -> bpf: skip the menu for deterministic dumps
    unsigned int input_count;         // host -> bpf: ordered transitions below
    unsigned int input_events[DOOM_INPUT_QUEUE_CAPACITY];
    struct capsule_result capsule; // bpf -> host: result of the last entry
    unsigned int error_len;        // bpf -> host: bytes valid in error_text
    char error_text[252];          // first PureDOOM "Error:" message, NUL-terminated
};
