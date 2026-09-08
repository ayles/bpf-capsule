// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "bpf_capsule.h"
#include "integer_ops.h"

volatile struct {
    struct capsule_result capsule;
    uint64_t cases;
    uint32_t count, completed;
} integer_state SEC(".data.integer_test");

static uint32_t evaluate(struct integer_case* cases, uint32_t count) {
    for (uint32_t i = 0; i < count; ++i) {
        integer_evaluate(&cases[i]);
    }
    return count;
}

SEC("syscall")
int integer_run(void) {
    integer_state.capsule = capsule_call((uint32_t*)&integer_state.completed, evaluate, (struct integer_case*)integer_state.cases, integer_state.count);
    return 0;
}

SEC("syscall")
int integer_drain(void) {
    integer_state.capsule = capsule_continue((uint32_t*)&integer_state.completed, integer_state.capsule.continuation);
    return 0;
}
char _license[] SEC("license") = "GPL";
