// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
// Kernel side of the standalone example.
//
// The host places an expression in Capsule memory; the managed root parses it
// with the ordinary recursive evaluator in expr.c.
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#include "bpf_capsule.h"

#include "expr_ctrl.h"
#include "expr.h"

struct expr_bpf_ctrl ectrl SEC(".data.ectrl");

static int64_t expr_run_root(void) {
    int64_t value = 0;
    size_t error_at = 0;
    ectrl.parse_error = expr_eval(ectrl.input, ectrl.input_size, &value, &error_at);
    ectrl.error_at = error_at;
    return value;
}

SEC("syscall")
int expr_run(void) {
    ectrl.capsule = capsule_call(&ectrl.value, expr_run_root);
    return 0;
}

SEC("syscall")
int expr_drain(void) {
    ectrl.capsule = capsule_continue(&ectrl.value, ectrl.capsule.continuation);
    return 0;
}

char _license[] SEC("license") = "GPL";
