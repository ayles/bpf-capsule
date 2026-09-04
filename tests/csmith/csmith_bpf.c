// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#include "csmith_include.h"

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#include "bpf_capsule.h"
#include "csmith_case.h"

volatile struct csmith_test_result csmith_result SEC(".data.csmith");

static uint64_t run_csmith(void) {
    crc32_context = 0;
    (void)csmith_generated_main();
    return crc32_context;
}

SEC("syscall")
int csmith_run(void) {
    csmith_result.capsule = capsule_call(&csmith_result.checksum, run_csmith);
    return 0;
}

SEC("syscall")
int csmith_continue(void) {
    csmith_result.capsule = capsule_continue(&csmith_result.checksum, csmith_result.capsule.continuation);
    return 0;
}

char _license[] SEC("license") = "GPL";
