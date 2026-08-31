// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#include "bpf_capsule.h"
#include "bpf_capsule_abi.h"

// White-box probe: the runtime owns this table; the test inspects a
// control word directly to prove release semantics.
extern struct __bpf_capsule_fiber_control bpf_capsule_fibers[];
#include "fiber_scale.h"

volatile struct fiber_scale_result fiber_scale_output SEC(".data.fscale");
volatile unsigned int fiber_scale_leases[FIBER_SCALE_COUNT] SEC(".bss.fscaleids");

// Fiber 511's default 256 KiB stack begins in logical region 64. On the 5.15
// profile that is beyond the 32-map direct prefix, so completing this body
// proves that software-stack correctness does not depend on the one-region
// direct-pointer specialization.
static void fiber_scale_body(unsigned int seed) {
    unsigned int fiber = capsule_fiber_index();
    volatile unsigned char local[FIBER_SCALE_LOCAL_BYTES];
    uint64_t checksum = 0;

    for (unsigned int i = 0; i < FIBER_SCALE_LOCAL_BYTES; ++i) {
        local[i] = (unsigned char)((seed + i) ^ fiber);
    }
    for (unsigned int i = 0; i < FIBER_SCALE_LOCAL_BYTES; ++i) {
        checksum += (uint64_t)local[i] * (i + 1);
    }

    fiber_scale_output.observed_fiber = fiber;
    fiber_scale_output.checksum = checksum;
}

static void fiber_scale_count_body(void) {
    fiber_scale_output.active_fibers = capsule_fiber_count();
}

SEC("syscall")
int fiber_scale_count(void) {
    fiber_scale_output.call_status = __bpf_capsule_call(0, (void*)0, (void*)0, 0, 1, (void*)fiber_scale_count_body);
    return 0;
}

SEC("syscall")
int fiber_scale_high(void) {
    fiber_scale_output.call_status = __bpf_capsule_call(FIBER_SCALE_LAST, (void*)0, (void*)0, 0, 1, (void*)fiber_scale_body, FIBER_SCALE_SEED);
    fiber_scale_output.stack_cursor_zero = bpf_capsule_fibers[FIBER_SCALE_LAST].pc == 0;
    return 0;
}

SEC("syscall")
int fiber_scale_pool_acquire(void) {
    unsigned int slot = fiber_scale_output.acquire_attempts++;
    if (slot < FIBER_SCALE_COUNT) {
        unsigned int fiber = __bpf_capsule_fiber_acquire();
        fiber_scale_leases[slot] = fiber;
        if (fiber < FIBER_SCALE_COUNT) {
            fiber_scale_output.acquired++;
            fiber_scale_output.acquired_sum += fiber;
        } else {
            fiber_scale_output.acquire_failures++;
        }
    } else if (slot == FIBER_SCALE_COUNT) {
        unsigned int extra = __bpf_capsule_fiber_acquire();
        fiber_scale_output.exhausted = extra == __BPF_CAPSULE_NO_FIBER;
        if (extra < FIBER_SCALE_COUNT) {
            fiber_scale_output.acquire_failures++;
            (void)__bpf_capsule_fiber_release(extra);
        }
    } else {
        fiber_scale_output.acquire_failures++;
    }
    return 0;
}

SEC("syscall")
int fiber_scale_pool_release(void) {
    unsigned int slot = fiber_scale_output.release_attempts++;
    if (slot < FIBER_SCALE_COUNT) {
        unsigned int fiber = fiber_scale_leases[slot];
        if (fiber >= FIBER_SCALE_COUNT || __bpf_capsule_fiber_release(fiber)) {
            fiber_scale_output.release_failures++;
        }
    } else if (slot == FIBER_SCALE_COUNT) {
        unsigned int recycled = __bpf_capsule_fiber_acquire();
        fiber_scale_output.recycled = recycled < FIBER_SCALE_COUNT;
        if (recycled >= FIBER_SCALE_COUNT || __bpf_capsule_fiber_release(recycled)) {
            fiber_scale_output.release_failures++;
        }
    } else {
        fiber_scale_output.release_failures++;
    }
    return 0;
}

char _license[] SEC("license") = "GPL";
