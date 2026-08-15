// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#ifdef RUST_OH_TRANSFORMED
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#include "bpf_capsule.h"
#else
#include "bpf_capsule.h"
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#endif

#include "overhead_ctrl.h"

#define RUST_OH_PACKET_COUNT 16u
#define RUST_OH_PACKET_BYTES 128u
#define RUST_OH_INPUT_BYTES (RUST_OH_PACKET_COUNT * RUST_OH_PACKET_BYTES)

unsigned char rust_oh_input[RUST_OH_INPUT_BYTES] SEC(".data.rohinput");
struct rust_oh_control rust_oh_ctrl SEC(".data.rohctrl");

extern uint64_t rust_oh_workload(void);

// rustc requires a panic handler for a no_std static library. The benchmark's
// unsafe masked accessor and wrapping arithmetic make this path unreachable.
// Both builds mimic the Rust convention of exiting 101 on panic: the
// transformed build ends the managed computation, the direct build fakes the
// same terminal record by hand.
void rust_oh_abort(void) {
#ifdef RUST_OH_TRANSFORMED
    capsule_exit(101);
#else
    rust_oh_ctrl.capsule.status = CAPSULE_EXITED;
    rust_oh_ctrl.capsule.code = 101;
#endif
}

SEC("syscall")
int rust_overhead_empty(void) {
    return 0;
}

static void rust_overhead_body(void) {
    rust_oh_ctrl.digest = rust_oh_workload();
}

SEC("syscall")
int rust_overhead_run(void) {
#ifdef RUST_OH_TRANSFORMED
    rust_oh_ctrl.capsule = capsule_call_void(rust_overhead_body);
#else
    rust_overhead_body();
    if (rust_oh_ctrl.capsule.status != CAPSULE_EXITED) {
        rust_oh_ctrl.capsule = (struct capsule_result){.status = CAPSULE_OK};
    }
#endif
    return 0;
}

#ifdef RUST_OH_TRANSFORMED
SEC("syscall")
int rust_overhead_drain(void) {
    rust_oh_ctrl.capsule = capsule_continue_void(rust_oh_ctrl.capsule.continuation);
    return 0;
}
#endif

char _license[] SEC("license") = "GPL";
