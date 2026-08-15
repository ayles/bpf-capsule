// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#include "bpf_capsule.h"

#define ARENA_INIT_LANES 8u
#define ARENA_INIT_WORDS (128u * 1024u)

// A non-trivial zero span keeps simultaneous first entries inside arena page
// allocation long enough to exercise the old multiple-base race. The pointer
// is initialized separately, so the same test also requires the generated
// pointer fixup to finish before any lane enters.
static volatile uint64_t arena_init_sparse[ARENA_INIT_WORDS];
static volatile uint64_t* volatile arena_init_pointer = &arena_init_sparse[4096];
volatile unsigned int arena_init_mask SEC(".data.ainit");

#define ARENA_INIT_LANE(index) \
    static void arena_init_body##index(void) { \
        arena_init_pointer[(index) * 4096u] = 0xabc0000000000000ull | (index); \
    } \
    SEC("syscall") \
    int arena_init_lane##index(void) { \
        struct capsule_result result = capsule_call_void(arena_init_body##index); \
        return result.status == CAPSULE_OK ? 0 : -5; \
    }

ARENA_INIT_LANE(0)
ARENA_INIT_LANE(1)
ARENA_INIT_LANE(2)
ARENA_INIT_LANE(3)
ARENA_INIT_LANE(4)
ARENA_INIT_LANE(5)
ARENA_INIT_LANE(6)
ARENA_INIT_LANE(7)

static void arena_init_verify_body(void) {
    unsigned int mask = 0;
    for (unsigned int lane = 0; lane < ARENA_INIT_LANES; ++lane) {
        if (arena_init_pointer[lane * 4096u] == (0xabc0000000000000ull | lane)) {
            mask |= 1u << lane;
        }
    }
    arena_init_mask = mask;
}

SEC("syscall")
int arena_init_verify(void) {
    struct capsule_result result = capsule_call_void(arena_init_verify_body);
    return result.status == CAPSULE_OK ? 0 : -5;
}

char _license[] SEC("license") = "GPL";
