// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#include "bpf_capsule.h"
#include "nosuspend_test.h"

volatile struct nosuspend_result nosuspend_output SEC(".data.nsresult");
volatile uint64_t nosuspend_input SEC(".data.nsinput") = 7;

__attribute__((noinline)) static uint64_t nosuspend_private(uint64_t value) {
    return (value * 17 + 3) ^ 0x5a5a;
}

// This deliberately has external linkage. Flattening the critical operation
// must retire the now-unreachable original API and its private call tree;
// leaving that copy behind used to make the domain checker reject clean
// QuickJS, wasm3, Rust and Doom builds.
__attribute__((noinline)) uint64_t nosuspend_public_api(uint64_t value) {
    return nosuspend_private(value) + 11;
}

__attribute__((noinline)) uint64_t __bpf_capsule_nosuspend_contract(uint64_t value) {
    return nosuspend_public_api(value);
}

static void nosuspend_body(void) {
    nosuspend_output.value = __bpf_capsule_nosuspend_contract(nosuspend_input);
}

SEC("syscall")
int nosuspend_run(void) {
    struct capsule_result result = capsule_call_void(nosuspend_body);
    nosuspend_output.status = result.status;
    nosuspend_output.code = result.code;
    return 0;
}

char _license[] SEC("license") = "GPL";
