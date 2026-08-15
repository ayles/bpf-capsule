// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
// Kernel side of the standalone example.
//
// The guest owns the input buffer: expr_prepare publishes its address and
// capacity, the host writes the expression bytes there, the kernel parses
// and evaluates them with the recursive evaluator in expr.c, and the host
// compares the result against the same sources compiled natively.
//
// The driver: owns the control map, defines the entry points, and calls
// ordinary C from them. Everything else stays BPF-unaware.
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#include "bpf_capsule.h"

#include "expr_ctrl.h"
#include "expr.h"

struct expr_bpf_ctrl ectrl SEC(".data.ectrl");

// Ordinary unsectioned storage: Capsule picks the kernel representation and
// managed code reads it through a plain pointer.
static char expr_input[4096];

static void expr_prepare_body(void) {
    ectrl.input.address = (uint64_t)(void*)expr_input;
    ectrl.input.capacity = sizeof(expr_input);
}

// The managed root: ordinary C from here on, recursion as deep as the input
// nests.
static int64_t expr_run_root(uint64_t length) {
    ectrl.status = EXPR_STAGE_ENTERED;

    int64_t value = 0;
    unsigned long error_at = 0;
    if (expr_eval(expr_input, length, &value, &error_at)) {
        ectrl.error_at = error_at;
        ectrl.status = EXPR_ERROR_PARSE;
        return 0;
    }
    ectrl.status = EXPR_STAGE_DONE;
    return value;
}

SEC("syscall")
int expr_prepare() {
    ectrl.capsule = capsule_call_void(expr_prepare_body);
    return 0;
}

// An entry runs a bounded slice of the software call stack. capsule_call
// writes the root's return value to ectrl.value when the computation
// completes; the Capsule result reports completion, a continuation to drain,
// or an error.
SEC("syscall")
int expr_run() {
    if (!ectrl.input.size) {
        ectrl.status = EXPR_ERROR_BAD_LEN;
        return 0;
    }
    ectrl.capsule = capsule_call(&ectrl.value, expr_run_root, ectrl.input.size);
    return 0;
}

// One more slice: the host calls this while expr_run remains pending.
SEC("syscall")
int expr_drain() {
    ectrl.capsule = capsule_continue(&ectrl.value, ectrl.capsule.continuation);
    return 0;
}

char _license[] SEC("license") = "GPL";
