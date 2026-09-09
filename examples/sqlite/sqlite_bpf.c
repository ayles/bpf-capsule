// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
// Stock SQLite in the kernel: the amalgamation with soft-float SQL, Capsule's
// allocator and an in-memory-only VFS executes one SQL script staged by the
// host. The runner itself is shared with the native comparison build
// (sqlite_runner.h).
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#include "bpf_capsule.h"

#include "sqlite_runner.h"

struct sqlite_bpf_ctrl sctrl SEC(".data.sctrl");

// The runner works on copies of the buffer descriptors in Capsule memory; only
// the resulting sizes and the result code go back to the control block.
static struct sqlite_buffer sqlite_script_buffer;
static struct sqlite_buffer sqlite_output_buffer;
static struct sqlite_buffer sqlite_error_buffer;

static void sqlite_run_body(void) {
    sctrl.output.size = 0;
    sctrl.error.size = 0;
    if (!sctrl.script.address || sctrl.script.size >= sctrl.script.capacity || !sctrl.output.address || !sctrl.output.capacity || !sctrl.error.address ||
        !sctrl.error.capacity) {
        capsule_exit(1);
    }
    sqlite_script_buffer = sctrl.script;
    sqlite_output_buffer = sctrl.output;
    sqlite_error_buffer = sctrl.error;
    int rc = sqlite_runner_run(&sqlite_script_buffer, &sqlite_output_buffer, &sqlite_error_buffer);
    sctrl.output.size = sqlite_output_buffer.size;
    sctrl.error.size = sqlite_error_buffer.size;
    sctrl.sqlite_rc = rc;
    if (rc) {
        capsule_exit(1);
    }
}

SEC("syscall")
int sqlite_run(void) {
    sctrl.capsule = capsule_call_void(sqlite_run_body);
    return 0;
}

SEC("syscall")
int sqlite_drain(void) {
    sctrl.capsule = capsule_continue_void(sctrl.capsule.continuation);
    return 0;
}

char _license[] SEC("license") = "GPL";
