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

// More than a thousand pointer initializers, including pointers to both
// sparse and initialized globals. The small test exercises initializer
// scaling without needing an interpreter-sized managed program.
struct fixup_node {
    uint64_t value;
    volatile uint64_t* pointers[32];
};
#define REPEAT8(p) p, p, p, p, p, p, p, p
// clang-format off
#define FIXUP_NODES(X) \
    X(0) X(1) X(2) X(3) X(4) X(5) X(6) X(7) \
    X(8) X(9) X(10) X(11) X(12) X(13) X(14) X(15) \
    X(16) X(17) X(18) X(19) X(20) X(21) X(22) X(23) \
    X(24) X(25) X(26) X(27) X(28) X(29) X(30) X(31)
// clang-format on
#define FIXUP_NODE(n) \
    static volatile struct fixup_node node##n = { \
        n, {REPEAT8(&arena_init_sparse[n]), REPEAT8(&arena_init_sparse[n]), REPEAT8(&arena_init_sparse[n]), REPEAT8(&arena_init_sparse[n])}};
FIXUP_NODES(FIXUP_NODE)
#define FIXUP_POINTER(n) &node##n,
static volatile struct fixup_node* volatile fixup_nodes[] = {FIXUP_NODES(FIXUP_POINTER)};
#undef FIXUP_POINTER
#undef FIXUP_NODE
#undef FIXUP_NODES
#undef REPEAT8

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
    for (unsigned int node = 0; node < 32; ++node) {
        volatile struct fixup_node* value = fixup_nodes[node];
        if (value->value != node) {
            arena_init_mask = 0;
            return;
        }
        for (unsigned int pointer = 0; pointer < 32; ++pointer) {
            if (value->pointers[pointer] != &arena_init_sparse[node]) {
                arena_init_mask = 0;
                return;
            }
        }
    }
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
