// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#ifdef OH_TRANSFORMED
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#include "bpf_capsule.h"
#else
#include "bpf_capsule.h"
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#endif

#include "workload.h"
#include "overhead_ctrl.h"

oh_u8 oh_input[OH_INPUT_BYTES] SEC(".data.ohinput");
struct oh_control oh_ctrl SEC(".data.ohctrl");

SEC("syscall")
int overhead_empty(void) {
    return 0;
}

static void overhead_empty_body(void) {
}

SEC("syscall")
int overhead_capsule_empty(void) {
#ifdef OH_TRANSFORMED
    oh_ctrl.capsule = capsule_call_void(overhead_empty_body);
#endif
    return 0;
}

static void overhead_body(void) {
    struct oh_result result;
    oh_workload(&result);
    oh_ctrl.digest = result.digest;
    oh_ctrl.accepted = result.accepted;
    oh_ctrl.parsed = result.parsed;
}

SEC("syscall")
int overhead_run(void) {
#ifdef OH_TRANSFORMED
    oh_ctrl.capsule = capsule_call_void(overhead_body);
#else
    overhead_body();
    oh_ctrl.capsule = (struct capsule_result){.status = CAPSULE_OK};
#endif
    return 0;
}

#ifdef OH_TRANSFORMED
SEC("syscall")
int overhead_drain(void) {
    oh_ctrl.capsule = capsule_continue_void(oh_ctrl.capsule.continuation);
    return 0;
}
#endif

char _license[] SEC("license") = "GPL";
