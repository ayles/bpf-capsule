// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
// C driver for the Rust-in-kernel test: the entry convention, the control
// block and the freestanding libc are shared with every other port; the work
// itself lives in lib.rs.
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#include "bpf_capsule.h"
#include "rust_ctrl.h"

struct rust_bpf_ctrl rctrl SEC(".data.rctrl");

extern uint64_t rust_run(uint64_t n);
extern void rust_force_panic(void);

static void rust_run_body(void) {
    rctrl.status = RUST_STAGE_STARTED;
    rctrl.result = rust_run(1000);
    rctrl.status = RUST_STAGE_COMPLETE;
}

SEC("syscall")
int rust_entry() {
    rctrl.capsule = capsule_call_void(rust_run_body);
    return 0;
}

SEC("syscall")
int rust_drain() {
    rctrl.capsule = capsule_continue_void(rctrl.capsule.continuation);
    return 0;
}

static void rust_panic_body(void) {
    rust_force_panic();
}

SEC("syscall")
int rust_panic_entry() {
    rctrl.capsule = capsule_call_void(rust_panic_body);
    return 0;
}

char _license[] SEC("license") = "GPL";
