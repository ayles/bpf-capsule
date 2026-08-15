// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#include "bpf_capsule.h"
#include "fib.h"

volatile struct fib_state fib_state SEC(".data.fib");

static unsigned int fib(unsigned int n) {
    return n < 2 ? n : fib(n - 1) + fib(n - 2);
}

SEC("syscall")
int fib_run(void) {
    fib_state.result = capsule_call(&fib_state.output, fib, fib_state.input);
    return 0;
}

char _license[] SEC("license") = "GPL";
