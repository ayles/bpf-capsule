// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
// Regression: an arena/global-init prologue must not split fixed native BPF
// stack allocations out of an entry block. LLVM's BPF backend diagnoses such
// a split as an unsupported dynamic stack allocation.
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#include "bpf_capsule.h"

static unsigned long arena_prologue_sparse[1024];
static volatile signed char arena_prologue_signed[1024];
volatile unsigned long arena_prologue_result SEC(".data.apresult");

static void arena_prologue_body(unsigned int index) {
    arena_prologue_sparse[index & 1023u] = 0xabc00000u | index;
    arena_prologue_signed[index & 1023u] = -17;
    arena_prologue_result = (unsigned long)arena_prologue_signed[index & 1023u];
}

SEC("syscall")
int arena_prologue_test(void) {
    // Volatile keeps genuine fixed allocas in the native entry after O2.
    volatile unsigned long slots[4] = {3, 5, 7, 11};
    volatile struct capsule_result result = capsule_call_void(arena_prologue_body, 17u);
    arena_prologue_result += slots[0] + slots[3] + result.status;
    return 0;
}

char _license[] SEC("license") = "GPL";
