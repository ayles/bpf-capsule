// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
// Stock QuickJS in the kernel. Scripts and batch stdin come from Capsule
// memory; console output and uncaught exceptions go back to it. The runner
// itself is shared with the native comparison build (quickjs_runner.h).
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#include "bpf_capsule.h"

#include "quickjs_runner.h"

struct quickjs_bpf_ctrl qctrl SEC(".data.qctrl");

// The runner works on copies of the buffer descriptors in Capsule memory; only
// the resulting sizes go back to the control block.
static struct qjs_buffer qjs_script;
static struct qjs_buffer qjs_input;
static struct qjs_buffer qjs_output;
static struct qjs_buffer qjs_error;

static void quickjs_run_body(void) {
    qctrl.output.size = 0;
    qctrl.error.size = 0;
    if (!qctrl.script.address || qctrl.script.size >= qctrl.script.capacity || !qctrl.input.address || qctrl.input.size > qctrl.input.capacity ||
        !qctrl.output.address || !qctrl.output.capacity || !qctrl.error.address || !qctrl.error.capacity) {
        capsule_exit(1);
    }
    qjs_script = qctrl.script;
    qjs_input = qctrl.input;
    qjs_output = qctrl.output;
    qjs_error = qctrl.error;
    int failed = qjs_runner_run(&qjs_script, &qjs_input, &qjs_output, &qjs_error);
    qctrl.output.size = qjs_output.size;
    qctrl.error.size = qjs_error.size;
    if (failed) {
        capsule_exit(1);
    }
}

SEC("syscall")
int quickjs_run(void) {
    qctrl.capsule = capsule_call_void(quickjs_run_body);
    return 0;
}

SEC("syscall")
int quickjs_drain(void) {
    qctrl.capsule = capsule_continue_void(qctrl.capsule.continuation);
    return 0;
}

char _license[] SEC("license") = "GPL";
