// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
// The public Capsule boundary is C; the managed workload itself is Rust.
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#include "bpf_capsule.h"
#include "rust_ctrl.h"

struct rust_bpf_ctrl rctrl SEC(".data.rctrl");

extern uint64_t rust_run(uint64_t n);
extern void rust_force_panic(void) __attribute__((noreturn));

SEC("syscall")
int rust_entry(void) {
    rctrl.capsule = capsule_call(&rctrl.checksum, rust_run, 1000ull);
    return 0;
}

SEC("syscall")
int rust_drain(void) {
    rctrl.capsule = capsule_continue(&rctrl.checksum, rctrl.capsule.continuation);
    return 0;
}

SEC("syscall")
int rust_panic_entry(void) {
    rctrl.capsule = capsule_call_void(rust_force_panic);
    return 0;
}

SEC("syscall")
int rust_panic_drain(void) {
    rctrl.capsule = capsule_continue_void(rctrl.capsule.continuation);
    return 0;
}

char _license[] SEC("license") = "GPL";
