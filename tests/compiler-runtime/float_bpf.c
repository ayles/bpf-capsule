// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "bpf_capsule.h"
#include "float_ops.h"

volatile struct {
    struct capsule_result capsule;
    uint64_t cases;
    uint32_t count, completed;
} float_state SEC(".data.float_test");

static uint32_t evaluate(struct float_case* cases, uint32_t count) {
    for (uint32_t i = 0; i < count; ++i) {
        float_evaluate(&cases[i]);
    }
    return count;
}

SEC("syscall")
int float_run(void) {
    float_state.capsule = capsule_call((uint32_t*)&float_state.completed, evaluate, (struct float_case*)float_state.cases, float_state.count);
    return 0;
}

SEC("syscall")
int float_drain(void) {
    float_state.capsule = capsule_continue((uint32_t*)&float_state.completed, float_state.capsule.continuation);
    return 0;
}
char _license[] SEC("license") = "GPL";
