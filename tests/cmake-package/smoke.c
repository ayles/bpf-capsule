// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#include "bpf_capsule.h"
#include "smoke.h"

char _license[] SEC("license") = "GPL";

volatile struct smoke_result result SEC(".data.smoke");
volatile int input SEC(".data.smoke") = 18;

extern int smoke_cpp_mix(int value);

static int fib(int n) {
    return n < 2 ? n : fib(n - 1) + fib(n - 2);
}

static int sum7(int a, int b, int c, int d, int e, int f, int g) {
    return a + b + c + d + e + f + g;
}

static int descend(int n) {
    return n ? 1 + descend(n - 1) : 0;
}

static void smoke_body(void) {
    int (*volatile indirect)(int, int, int, int, int, int, int) = sum7;
    int n = input;
    result.recursion = fib(n);
    result.many_args = indirect(n, 2, 3, 4, 5, 6, 7);
    result.depth = descend(n + 46);
    result.cpp = smoke_cpp_mix(n);
}

SEC("syscall")
int package_smoke(void* context) {
    (void)context;
    result.capsule = capsule_call_void(smoke_body);
    return 0;
}
