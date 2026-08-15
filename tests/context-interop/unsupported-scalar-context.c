// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#include "bpf_capsule.h"

const volatile unsigned int scalar_mode SEC(".rodata.scalarctx") = 1;

static __attribute__((noinline)) void context_leaf(void) {
    void* context = capsule_borrowed_ctx();
    asm volatile("" : : "r"(context));
}

static __attribute__((noinline)) void mixed_body(unsigned int initialize) {
    if (!initialize) {
        context_leaf();
    }
}

static void context_root(struct xdp_md* context) {
    (void)context;
    mixed_body(0);
}

SEC("syscall")
int invalid_scalar_root(void) {
    (void)capsule_call_void(mixed_body, scalar_mode);
    return 0;
}

SEC("xdp")
int context_root_entry(struct xdp_md* context) {
    (void)capsule_call_void(context_root, context);
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
