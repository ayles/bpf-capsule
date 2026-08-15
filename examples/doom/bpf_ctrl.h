// SPDX-License-Identifier: GPL-2.0-only
// Control block shared between the BPF program (doom_bpf.c) and its host.
// Lives in the .data.ctrl map, which libbpf mmaps, so both sides just read and
// write it -- no syscall on the frame path. Fixed-offset scalars only, so
// every access is verifier-trivial.
#pragma once

#include "bpf_capsule_abi.h"

// Input crosses the userspace/kernel boundary between game tics.  Keep every
// transition in order: reducing a burst to one "latest down" and one "latest
// up" loses taps and can replay a release before its press.
#define DOOM_INPUT_QUEUE_CAPACITY 64u
#define DOOM_INPUT_DOWN (1u << 31)
#define DOOM_INPUT_KEY_MASK 0xffffu

struct doom_bpf_ctrl {
    uint64_t wad_size;        // host -> bpf: total WAD size
    uint64_t wad_addr;        // bpf -> host: address in capsule memory
    uint64_t wad_capacity;    // bpf -> host: reserved bytes at wad_addr
    uint64_t want_frame;      // host -> bpf: export the RGBA framebuffer
    uint64_t autostart;       // host -> bpf: start directly in E1M1
    unsigned int input_count; // host -> bpf: ordered transitions below
    unsigned int input_events[DOOM_INPUT_QUEUE_CAPACITY];
    int inited; // bpf: doom_init done
    int pad_;
    struct capsule_result capsule; // bpf -> host: completion/continuation/error
    unsigned int error_len;        // bpf -> host: bytes valid in error_text
    char error_text[252];          // first PureDOOM "Error:" message, NUL-terminated
};
