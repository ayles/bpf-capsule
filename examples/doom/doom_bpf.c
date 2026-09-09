// SPDX-License-Identifier: GPL-2.0-only
// DOOM's kernel side: the entry points userspace invokes around the engine
// steps shared with the native build (doom_engine.h). Everything that makes
// ordinary C runnable in the kernel lives in the runtime header and the
// passes, not here.

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#include "bpf_capsule.h"
#include "bpf_ctrl.h"

char _license[] SEC("license") = "GPL";

// The one page userspace and the kernel both reach directly. Everything else
// lives in the relocated address space and is reached by the address reported
// here.
volatile struct doom_bpf_ctrl ctrl SEC(".data.ctrl");

// Preserve the engine's first fatal message in the mmapped control map so the
// host can explain the abort that follows it.
static void doom_record_error(const char* text, int length) {
    if (ctrl.error_len) {
        return;
    }
    unsigned int copy = length < (int)sizeof(ctrl.error_text) - 1 ? (unsigned int)length : (unsigned int)sizeof(ctrl.error_text) - 1;
    for (unsigned int i = 0; i < copy; ++i) {
        ctrl.error_text[i] = text[i];
    }
    ctrl.error_text[copy] = 0;
    ctrl.error_len = copy;
}

#define DOOM_ENGINE_EXIT(code) capsule_exit(code)
#define DOOM_ENGINE_ERROR(text, length) doom_record_error((text), (length))
#include "doom_engine.h"

// Engine start-up as its own managed body: WAD parsing, zone setup and the
// initial level load are far heavier than any frame, so they run once behind
// their own entry instead of hiding inside the first frame.
static void doom_start_body(void) {
    doom_engine_start(ctrl.wad, ctrl.wad_size, ctrl.start_in_e1m1);
}

SEC("syscall")
int doom_start(void) {
    ctrl.capsule = capsule_call_void(doom_start_body);
    return 0;
}

// One frame: advance the game and render it. The whole frame is one managed
// body: every piece must run in order on the software stack, and only ctrl
// bookkeeping stays in the entry.
static void doom_frame_body(void) {
    unsigned count = ctrl.input_count;
    if (count > DOOM_INPUT_QUEUE_CAPACITY) {
        count = DOOM_INPUT_QUEUE_CAPACITY;
    }
    unsigned int events[DOOM_INPUT_QUEUE_CAPACITY];
    for (unsigned i = 0; i < count; i++) {
        events[i] = ctrl.input_events[i];
    }
    ctrl.input_count = 0;
    ctrl.framebuffer = doom_engine_frame(events, count);
}

SEC("syscall")
int doom_frame(void) {
    ctrl.capsule = capsule_call_void(doom_frame_body);
    return 0;
}
