// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
// Pipeline smoke: the smallest complete Capsule program. Recursion is the
// point — it cannot work without the software stack, so a green run proves
// the whole pipeline (clang -> link -> opt -> llc -> skeleton -> configure ->
// load -> run) and the core of the transform at once.
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#include "bpf_capsule.h"
#include "smoke.h"

volatile struct smoke_state smoke_state SEC(".data.smoke");

static uint32_t fib(uint32_t n) {
    return n < 2 ? n : fib(n - 1) + fib(n - 2);
}

SEC("syscall")
int smoke_run(void) {
    smoke_state.capsule = capsule_call((uint32_t*)&smoke_state.output, fib, smoke_state.input);
    return 0;
}

SEC("syscall")
int smoke_drain(void) {
    smoke_state.capsule = capsule_continue((uint32_t*)&smoke_state.output, smoke_state.capsule.continuation);
    return 0;
}

char _license[] SEC("license") = "GPL";
