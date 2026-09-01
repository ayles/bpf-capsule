// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
// Matched code-generation microcases.  The direct programs establish the BPF
// ISA/JIT floor; their Capsule twins expose only continuation dispatch,
// software-frame and arbitrary-address memory costs.
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#include "bpf_capsule.h"
#include "overhead.h"

volatile struct overhead_state overhead_state SEC(".data.overhead");

// No section: Capsule owns this storage and presents its address as a logical
// guest address.  Loading that address through the sectioned control record
// prevents the memory pass from replacing the benchmark with a static-global
// fast path.
static uint64_t logical_words[OVERHEAD_MEMORY_WORDS];

struct logical_node {
    struct logical_node* next;
    uint64_t value;
};

static struct logical_node logical_nodes[OVERHEAD_MEMORY_WORDS];

#define ARITHMETIC_STEP(value, index) ((value) * 1664525u + (uint64_t)(index) + 1013904223u)

static uint64_t managed_empty(void) {
    return 1;
}

static uint64_t managed_arithmetic(uint32_t trips) {
    uint64_t value = 7;
    if (trips > OVERHEAD_ARITHMETIC_TRIPS) {
        trips = OVERHEAD_ARITHMETIC_TRIPS;
    }
    for (uint32_t index = 0; index < trips; ++index) {
        value = ARITHMETIC_STEP(value, index);
    }
    return value;
}

static uint64_t managed_modulo(uint32_t trips) {
    int64_t value = 7;
    if (trips > OVERHEAD_ARITHMETIC_TRIPS) {
        trips = OVERHEAD_ARITHMETIC_TRIPS;
    }
    for (uint32_t index = 0; index < trips; ++index) {
        value = (value + (int64_t)index * 17) % overhead_state.divisor;
    }
    return (uint64_t)value;
}

// The trip count deliberately has no compile-time ceiling. Stackify must turn
// this backedge into a continuation, unlike managed_arithmetic's verifier-
// native bounded loop.
static uint64_t managed_dynamic_loop(void) {
    uint64_t value = 7;
    for (uint32_t index = 0; index < overhead_state.trips; ++index) {
        value = ARITHMETIC_STEP(value, index);
    }
    return value;
}

__attribute__((noinline)) static uint64_t managed_dynamic_leaf(uint64_t value, uint32_t index) {
    // Keep this function in the managed call ABI. The branch is cold at run
    // time, but its possible recursion makes a native BPF call frame invalid.
    if (overhead_state.recurse) {
        return managed_dynamic_leaf(value, index);
    }
    return ARITHMETIC_STEP(value, index);
}

static uint64_t managed_dynamic_call_loop(void) {
    uint64_t value = 7;
    for (uint32_t index = 0; index < overhead_state.trips; ++index) {
        value = managed_dynamic_leaf(value, index);
    }
    return value;
}

__attribute__((noinline)) static uint64_t managed_byval_leaf(struct overhead_byval value, uint32_t index) {
    if (overhead_state.recurse) {
        return managed_byval_leaf(value, index);
    }
    return ARITHMETIC_STEP(value.first + (value.second ^ value.third), index);
}

static uint64_t managed_byval_call_loop(void) {
    uint64_t value = 7;
    for (uint32_t index = 0; index < overhead_state.trips; ++index) {
        struct overhead_byval argument = {value, value ^ 0x9e3779b97f4a7c15ull, index};
        value = managed_byval_leaf(argument, index);
    }
    return value;
}

static uint64_t managed_pressure_call_loop(void) {
    uint64_t a = 1, b = 2, c = 3, d = 4, e = 5, f = 6, g = 7, h = 8;
    for (uint32_t index = 0; index < overhead_state.trips; ++index) {
        uint64_t next = managed_dynamic_leaf(a + h, index);
        a = next + b;
        b ^= next + c;
        c += next ^ d;
        d = (d + e) ^ next;
        e += f ^ next;
        f = (f ^ g) + next;
        g += h + next;
        h ^= a + next;
    }
    return a ^ b ^ c ^ d ^ e ^ f ^ g ^ h;
}

// Values produced before the managed call but dead at the continuation must
// not acquire software-frame slots merely because they were once registers.
static uint64_t managed_dead_values_call_loop(void) {
    uint64_t value = 7;
    for (uint32_t index = 0; index < overhead_state.trips; ++index) {
        uint64_t a = value + index + 1, b = value + index + 2;
        uint64_t c = value + index + 3, d = value + index + 4;
        uint64_t e = value + index + 5, f = value + index + 6;
        uint64_t g = value + index + 7, h = value + index + 8;
        value = managed_dynamic_leaf(a ^ b ^ c ^ d ^ e ^ f ^ g ^ h, index);
    }
    return value;
}

// These values really are live across every call, but never change. This
// distinguishes necessary continuation reloads from needless repeated saves.
static uint64_t managed_invariant_values_call_loop(void) {
    uint64_t a = overhead_state.direct_words[0];
    uint64_t b = overhead_state.direct_words[1];
    uint64_t c = overhead_state.direct_words[2];
    uint64_t d = overhead_state.direct_words[3];
    uint64_t e = overhead_state.direct_words[4];
    uint64_t f = overhead_state.direct_words[5];
    uint64_t g = overhead_state.direct_words[6];
    uint64_t h = overhead_state.direct_words[7];
    uint64_t value = 7;
    for (uint32_t index = 0; index < overhead_state.trips; ++index) {
        uint64_t next = managed_dynamic_leaf(value, index);
        switch (index & 7u) {
        case 0: value = next ^ a; break;
        case 1: value = next ^ b; break;
        case 2: value = next ^ c; break;
        case 3: value = next ^ d; break;
        case 4: value = next ^ e; break;
        case 5: value = next ^ f; break;
        case 6: value = next ^ g; break;
        default: value = next ^ h; break;
        }
    }
    return value;
}

static __always_inline uint64_t schedulable_mix(
    uint64_t next, uint64_t a, uint64_t b, uint64_t c, uint64_t d,
    uint64_t e, uint64_t f, uint64_t g, uint64_t h) {
    uint32_t shift = next & 63u;
    uint32_t inverse = (-shift) & 63u;
    return next ^ ((a << shift) | (a >> inverse)) ^
           ((b >> shift) | (b << inverse)) ^
           (c * (next | 1u)) ^ (d + (next >> 7)) ^
           (e * (next | 3u)) ^ (f + (next >> 17)) ^
           (g * (next | 5u)) ^ (h + (next >> 29));
}

// The two loops are source-equivalent.  The first deliberately computes
// scalar-only values before a suspendable call even though they are used only
// after it; the second spells out the ideal scheduling explicitly.  Their
// difference measures avoidable continuation liveness.
static uint64_t managed_precomputed_values_call_loop(void) {
    uint64_t value = 7;
    for (uint32_t index = 0; index < overhead_state.trips; ++index) {
        uint64_t a = value * 3u + index, b = value * 5u + index;
        uint64_t c = value * 7u + index, d = value * 11u + index;
        uint64_t e = value * 13u + index, f = value * 17u + index;
        uint64_t g = value * 19u + index, h = value * 23u + index;
        uint64_t next = managed_dynamic_leaf(value, index);
        value = schedulable_mix(next, a, b, c, d, e, f, g, h);
    }
    return value;
}

static uint64_t managed_postcomputed_values_call_loop(void) {
    uint64_t value = 7;
    for (uint32_t index = 0; index < overhead_state.trips; ++index) {
        uint64_t next = managed_dynamic_leaf(value, index);
        uint64_t a = value * 3u + index, b = value * 5u + index;
        uint64_t c = value * 7u + index, d = value * 11u + index;
        uint64_t e = value * 13u + index, f = value * 17u + index;
        uint64_t g = value * 19u + index, h = value * 23u + index;
        value = schedulable_mix(next, a, b, c, d, e, f, g, h);
    }
    return value;
}

__attribute__((noinline)) static uint64_t managed_recursive_chain(uint32_t depth) {
    if (!depth) {
        return 1;
    }
    uint64_t child = managed_recursive_chain(depth - 1);
    // Preserve a genuine post-call continuation; the volatile condition is
    // false in the benchmark but prevents recursion-to-loop conversion.
    if (overhead_state.recurse) {
        child ^= overhead_state.recurse;
    }
    return child + depth;
}

__attribute__((noinline)) static uint64_t direct_dynamic_leaf(uint64_t value, uint32_t index) {
    return ARITHMETIC_STEP(value, index);
}

// A flat virtual-call executor whose complete working frame lives in the
// outer BPF program's native stack.  The three regions deliberately match the
// current managed call sequence: schedule call, execute callee, resume caller.
// No guest call is represented by a nested BPF call.
enum flat_pressure_pc {
    FLAT_PRESSURE_CALL,
    FLAT_PRESSURE_CALLEE,
    FLAT_PRESSURE_RESUME,
    FLAT_PRESSURE_DONE,
};

struct flat_pressure_context {
    uint64_t a, b, c, d, e, f, g, h;
    uint64_t argument;
    uint64_t result;
    uint32_t index;
    uint32_t trips;
    uint32_t pc;
};

static __always_inline long flat_pressure_step(struct flat_pressure_context* context) {
    switch (context->pc) {
    case FLAT_PRESSURE_CALL:
        context->argument = context->a + context->h;
        context->pc = FLAT_PRESSURE_CALLEE;
        return 0;
    case FLAT_PRESSURE_CALLEE: {
        context->result = ARITHMETIC_STEP(context->argument, context->index);
        context->pc = FLAT_PRESSURE_RESUME;
        return 0;
    }
    case FLAT_PRESSURE_RESUME: {
        uint64_t next = context->result;
        uint64_t a = next + context->b;
        context->b ^= next + context->c;
        context->c += next ^ context->d;
        context->d = (context->d + context->e) ^ next;
        context->e += context->f ^ next;
        context->f = (context->f ^ context->g) + next;
        context->g += context->h + next;
        context->h ^= a + next;
        context->a = a;
        context->index++;
        context->pc = context->index < context->trips ? FLAT_PRESSURE_CALL : FLAT_PRESSURE_DONE;
        return 0;
    }
    default:
        return 1;
    }
}

static long flat_stack_pressure_step_callback(uint32_t iteration, void* opaque) {
    (void)iteration;
    return flat_pressure_step(opaque);
}

struct flat_map_pressure_callback_context {
    struct flat_pressure_context* frame;
};

static long flat_map_pressure_step_callback(uint32_t iteration, void* opaque) {
    (void)iteration;
    struct flat_map_pressure_callback_context* context = opaque;
    return flat_pressure_step(context->frame);
}

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, uint32_t);
    __type(value, struct flat_pressure_context);
} flat_pressure_contexts SEC(".maps");

struct pressure_chunk_context {
    uint64_t a, b, c, d, e, f, g, h;
    uint32_t trips;
};

// Model the intended execution unit: bpf_loop supplies a verifier-modular
// outer bound, while each callback runs several ordinary BPF iterations and
// calls. State crosses the callback boundary once per chunk, not once per
// managed call. Keep the body looped, rather than duplicating it N times.
#define DEFINE_PRESSURE_CHUNK_CALLBACK(N)                                                        \
    static long pressure_chunk_callback_##N(uint32_t chunk, void* opaque) {                      \
        struct pressure_chunk_context* context = opaque;                                         \
        uint64_t a = context->a, b = context->b, c = context->c, d = context->d;                 \
        uint64_t e = context->e, f = context->f, g = context->g, h = context->h;                 \
        uint32_t first = chunk * (N);                                                             \
        _Pragma("clang loop unroll(disable)")                                                    \
        for (uint32_t offset = 0; offset < (N); ++offset) {                                      \
            uint32_t index = first + offset;                                                      \
            if (index >= context->trips)                                                          \
                break;                                                                            \
            uint64_t next = direct_dynamic_leaf(a + h, index);                                   \
            a = next + b;                                                                          \
            b ^= next + c;                                                                         \
            c += next ^ d;                                                                         \
            d = (d + e) ^ next;                                                                    \
            e += f ^ next;                                                                         \
            f = (f ^ g) + next;                                                                    \
            g += h + next;                                                                         \
            h ^= a + next;                                                                          \
        }                                                                                          \
        context->a = a;                                                                            \
        context->b = b;                                                                            \
        context->c = c;                                                                            \
        context->d = d;                                                                            \
        context->e = e;                                                                            \
        context->f = f;                                                                            \
        context->g = g;                                                                            \
        context->h = h;                                                                            \
        return 0;                                                                                  \
    }

DEFINE_PRESSURE_CHUNK_CALLBACK(1)
DEFINE_PRESSURE_CHUNK_CALLBACK(2)
DEFINE_PRESSURE_CHUNK_CALLBACK(4)
DEFINE_PRESSURE_CHUNK_CALLBACK(8)
DEFINE_PRESSURE_CHUNK_CALLBACK(16)
DEFINE_PRESSURE_CHUNK_CALLBACK(32)
DEFINE_PRESSURE_CHUNK_CALLBACK(64)

static uint64_t managed_memory64(void) {
    volatile uint64_t* words = (volatile uint64_t*)(unsigned long)overhead_state.logical_words;
    uint64_t value = 7;
    for (uint32_t index = 0; index < OVERHEAD_MEMORY_WORDS; ++index) {
        uint64_t next = ARITHMETIC_STEP(value + words[index], index);
        words[index] = next;
        value ^= next;
    }
    return value;
}

static uint64_t managed_combined(uint32_t trips) {
    volatile uint64_t* words = (volatile uint64_t*)(unsigned long)overhead_state.logical_words;
    uint64_t value = 7;
    if (trips > OVERHEAD_ARITHMETIC_TRIPS) {
        trips = OVERHEAD_ARITHMETIC_TRIPS;
    }
    for (uint32_t index = 0; index < trips; ++index) {
        uint32_t slot = index & (OVERHEAD_MEMORY_WORDS - 1u);
        uint64_t next = ARITHMETIC_STEP(value + words[slot], index);
        words[slot] = next;
        value ^= next;
    }
    return value;
}

// Unlike managed_memory64, every iteration obtains the address for the next
// access from guest memory. This is the pointer-rich access pattern used by
// interpreters and allocators; its address translation cannot be hoisted out
// of the loop.
static uint64_t managed_pointer_chase(uint32_t trips) {
    volatile struct logical_node* node = (volatile struct logical_node*)(unsigned long)overhead_state.logical_nodes;
    uint64_t value = 7;
    if (trips > OVERHEAD_ARITHMETIC_TRIPS) {
        trips = OVERHEAD_ARITHMETIC_TRIPS;
    }
    for (uint32_t index = 0; index < trips; ++index) {
        node = node->next;
        uint64_t next = ARITHMETIC_STEP(value + node->value, index);
        node->value = next;
        value ^= next;
    }
    return value;
}

static void managed_prepare(void) {
    overhead_state.logical_words = (uint64_t)(unsigned long)logical_words;
    overhead_state.logical_nodes = (uint64_t)(unsigned long)logical_nodes;
    for (uint32_t index = 0; index < OVERHEAD_MEMORY_WORDS; ++index) {
        uint32_t next = (index * 17u + 1u) & (OVERHEAD_MEMORY_WORDS - 1u);
        logical_nodes[index].next = &logical_nodes[next];
        logical_nodes[index].value = index;
    }
}

SEC("syscall")
int overhead_prepare(void) {
    overhead_state.capsule = capsule_call_void(managed_prepare);
    overhead_state.divisor = 1000003;
    overhead_state.trips = OVERHEAD_ARITHMETIC_TRIPS;
    overhead_state.recurse = 0;
    for (uint32_t index = 0; index < OVERHEAD_MEMORY_WORDS; ++index) {
        overhead_state.direct_nodes[index].next = (index * 17u + 1u) & (OVERHEAD_MEMORY_WORDS - 1u);
        overhead_state.direct_nodes[index].value = index;
    }
    return 0;
}

SEC("syscall")
int overhead_direct_empty(void) {
    overhead_state.result = 1;
    return 0;
}

SEC("syscall")
int overhead_capsule_empty(void) {
    overhead_state.capsule = capsule_call((uint64_t*)&overhead_state.result, managed_empty);
    return 0;
}

SEC("syscall")
int overhead_direct_arithmetic(void) {
    uint64_t value = 7;
    for (uint32_t index = 0; index < OVERHEAD_ARITHMETIC_TRIPS; ++index) {
        value = ARITHMETIC_STEP(value, index);
    }
    overhead_state.result = value;
    return 0;
}

SEC("syscall")
int overhead_capsule_arithmetic(void) {
    overhead_state.capsule = capsule_call((uint64_t*)&overhead_state.result, managed_arithmetic, OVERHEAD_ARITHMETIC_TRIPS);
    return 0;
}

SEC("syscall")
int overhead_direct_modulo(void) {
    int64_t value = 7;
    for (uint32_t index = 0; index < OVERHEAD_ARITHMETIC_TRIPS; ++index) {
        value = (value + (int64_t)index * 17) % overhead_state.divisor;
    }
    overhead_state.result = (uint64_t)value;
    return 0;
}

SEC("syscall")
int overhead_capsule_modulo(void) {
    overhead_state.capsule = capsule_call((uint64_t*)&overhead_state.result, managed_modulo, OVERHEAD_ARITHMETIC_TRIPS);
    return 0;
}

SEC("syscall")
int overhead_direct_dynamic_loop(void) {
    uint32_t trips = overhead_state.trips;
    if (trips > OVERHEAD_ARITHMETIC_TRIPS) {
        trips = OVERHEAD_ARITHMETIC_TRIPS;
    }
    uint64_t value = 7;
    for (uint32_t index = 0; index < trips; ++index) {
        value = ARITHMETIC_STEP(value, index);
    }
    overhead_state.result = value;
    return 0;
}

SEC("syscall")
int overhead_capsule_dynamic_loop(void) {
    overhead_state.capsule = capsule_call((uint64_t*)&overhead_state.result, managed_dynamic_loop);
    return 0;
}

SEC("syscall")
int overhead_direct_dynamic_call_loop(void) {
    uint32_t trips = overhead_state.trips;
    if (trips > OVERHEAD_ARITHMETIC_TRIPS) {
        trips = OVERHEAD_ARITHMETIC_TRIPS;
    }
    uint64_t value = 7;
    for (uint32_t index = 0; index < trips; ++index) {
        value = direct_dynamic_leaf(value, index);
    }
    overhead_state.result = value;
    return 0;
}

SEC("syscall")
int overhead_capsule_dynamic_call_loop(void) {
    overhead_state.capsule = capsule_call((uint64_t*)&overhead_state.result, managed_dynamic_call_loop);
    return 0;
}

SEC("syscall")
int overhead_capsule_byval_call_loop(void) {
    overhead_state.capsule = capsule_call((uint64_t*)&overhead_state.result, managed_byval_call_loop);
    return 0;
}

SEC("syscall")
int overhead_direct_pressure_call_loop(void) {
    uint32_t trips = overhead_state.trips;
    if (trips > OVERHEAD_ARITHMETIC_TRIPS) {
        trips = OVERHEAD_ARITHMETIC_TRIPS;
    }
    uint64_t a = 1, b = 2, c = 3, d = 4, e = 5, f = 6, g = 7, h = 8;
    for (uint32_t index = 0; index < trips; ++index) {
        uint64_t next = direct_dynamic_leaf(a + h, index);
        a = next + b;
        b ^= next + c;
        c += next ^ d;
        d = (d + e) ^ next;
        e += f ^ next;
        f = (f ^ g) + next;
        g += h + next;
        h ^= a + next;
    }
    overhead_state.result = a ^ b ^ c ^ d ^ e ^ f ^ g ^ h;
    return 0;
}

SEC("syscall")
int overhead_flat_stack_pressure_call_loop(void) {
    uint32_t trips = overhead_state.trips;
    if (trips > OVERHEAD_ARITHMETIC_TRIPS)
        trips = OVERHEAD_ARITHMETIC_TRIPS;
    struct flat_pressure_context context = {
        .a = 1, .b = 2, .c = 3, .d = 4, .e = 5, .f = 6, .g = 7, .h = 8,
        .trips = trips,
        .pc = FLAT_PRESSURE_CALL,
    };
    bpf_loop(3u * trips + 1u, flat_stack_pressure_step_callback, &context, 0);
    overhead_state.result = context.a ^ context.b ^ context.c ^ context.d ^
                            context.e ^ context.f ^ context.g ^ context.h;
    return 0;
}

SEC("syscall")
int overhead_flat_map_pressure_call_loop(void) {
    uint32_t trips = overhead_state.trips;
    if (trips > OVERHEAD_ARITHMETIC_TRIPS)
        trips = OVERHEAD_ARITHMETIC_TRIPS;
    uint32_t key = 0;
    struct flat_pressure_context* context = bpf_map_lookup_elem(&flat_pressure_contexts, &key);
    if (!context)
        return 0;
    context->a = 1; context->b = 2; context->c = 3; context->d = 4;
    context->e = 5; context->f = 6; context->g = 7; context->h = 8;
    context->index = 0;
    context->trips = trips;
    context->pc = FLAT_PRESSURE_CALL;
    struct flat_map_pressure_callback_context callback_context = { .frame = context };
    bpf_loop(3u * trips + 1u, flat_map_pressure_step_callback, &callback_context, 0);
    overhead_state.result = context->a ^ context->b ^ context->c ^ context->d ^
                            context->e ^ context->f ^ context->g ^ context->h;
    return 0;
}

SEC("syscall")
int overhead_maygoto_pressure_call_loop(void) {
    uint32_t trips = overhead_state.trips;
    uint64_t a = 1, b = 2, c = 3, d = 4, e = 5, f = 6, g = 7, h = 8;
    uint32_t index = 0;
    while (index < trips) {
        // The verifier may take this edge; at runtime it is only the safety
        // budget. The ordinary source exit normally wins first.
        asm volatile goto("may_goto %l[budget]" :::: budget);
        uint64_t next = direct_dynamic_leaf(a + h, index);
        a = next + b;
        b ^= next + c;
        c += next ^ d;
        d = (d + e) ^ next;
        e += f ^ next;
        f = (f ^ g) + next;
        g += h + next;
        h ^= a + next;
        ++index;
    }
    overhead_state.result = a ^ b ^ c ^ d ^ e ^ f ^ g ^ h;
    return 0;

budget:
    // A real Capsule lowering would save this state and resume in a fresh
    // invocation. Two thousand iterations should never consume the kernel's
    // may_goto safety budget, so reaching this label fails result validation.
    overhead_state.result = index;
    return 0;
}

SEC("syscall")
int overhead_iterator_pressure_call_loop(void) {
    uint32_t trips = overhead_state.trips;
    uint64_t a = 1, b = 2, c = 3, d = 4, e = 5, f = 6, g = 7, h = 8;
    int index;
    bpf_for(index, 0, (int)trips) {
        uint64_t next = direct_dynamic_leaf(a + h, (uint32_t)index);
        a = next + b;
        b ^= next + c;
        c += next ^ d;
        d = (d + e) ^ next;
        e += f ^ next;
        f = (f ^ g) + next;
        g += h + next;
        h ^= a + next;
    }
    overhead_state.result = a ^ b ^ c ^ d ^ e ^ f ^ g ^ h;
    return 0;
}

#define DEFINE_PRESSURE_CHUNK_PROGRAM(N)                                                         \
    SEC("syscall")                                                                                \
    int overhead_chunked_pressure_call_loop_##N(void) {                                          \
        uint32_t trips = overhead_state.trips;                                                     \
        if (trips > OVERHEAD_ARITHMETIC_TRIPS)                                                     \
            trips = OVERHEAD_ARITHMETIC_TRIPS;                                                     \
        struct pressure_chunk_context context = {                                                 \
            .a = 1, .b = 2, .c = 3, .d = 4, .e = 5, .f = 6, .g = 7, .h = 8, .trips = trips,       \
        };                                                                                         \
        uint32_t chunks = (trips + (N)-1u) / (N);                                                 \
        bpf_loop(chunks, pressure_chunk_callback_##N, &context, 0);                               \
        overhead_state.result = context.a ^ context.b ^ context.c ^ context.d ^                   \
                                context.e ^ context.f ^ context.g ^ context.h;                     \
        return 0;                                                                                  \
    }

DEFINE_PRESSURE_CHUNK_PROGRAM(1)
DEFINE_PRESSURE_CHUNK_PROGRAM(2)
DEFINE_PRESSURE_CHUNK_PROGRAM(4)
DEFINE_PRESSURE_CHUNK_PROGRAM(8)
DEFINE_PRESSURE_CHUNK_PROGRAM(16)
DEFINE_PRESSURE_CHUNK_PROGRAM(32)
DEFINE_PRESSURE_CHUNK_PROGRAM(64)

SEC("syscall")
int overhead_capsule_pressure_call_loop(void) {
    overhead_state.capsule = capsule_call((uint64_t*)&overhead_state.result, managed_pressure_call_loop);
    return 0;
}

SEC("syscall")
int overhead_capsule_dead_values_call_loop(void) {
    overhead_state.capsule = capsule_call((uint64_t*)&overhead_state.result, managed_dead_values_call_loop);
    return 0;
}

SEC("syscall")
int overhead_capsule_invariant_values_call_loop(void) {
    overhead_state.capsule = capsule_call((uint64_t*)&overhead_state.result, managed_invariant_values_call_loop);
    return 0;
}

SEC("syscall")
int overhead_capsule_precomputed_values_call_loop(void) {
    overhead_state.capsule = capsule_call((uint64_t*)&overhead_state.result, managed_precomputed_values_call_loop);
    return 0;
}

SEC("syscall")
int overhead_capsule_postcomputed_values_call_loop(void) {
    overhead_state.capsule = capsule_call((uint64_t*)&overhead_state.result, managed_postcomputed_values_call_loop);
    return 0;
}

SEC("syscall")
int overhead_capsule_recursive_chain(void) {
    overhead_state.capsule = capsule_call(
        (uint64_t*)&overhead_state.result, managed_recursive_chain, OVERHEAD_RECURSION_DEPTH);
    return 0;
}

SEC("syscall")
int overhead_direct_memory64(void) {
    uint64_t value = 7;
    for (uint32_t index = 0; index < OVERHEAD_MEMORY_WORDS; ++index) {
        uint64_t next = ARITHMETIC_STEP(value + overhead_state.direct_words[index], index);
        overhead_state.direct_words[index] = next;
        value ^= next;
    }
    overhead_state.result = value;
    return 0;
}

SEC("syscall")
int overhead_capsule_memory64(void) {
    overhead_state.capsule = capsule_call((uint64_t*)&overhead_state.result, managed_memory64);
    return 0;
}

SEC("syscall")
int overhead_direct_combined(void) {
    uint64_t value = 7;
    for (uint32_t index = 0; index < OVERHEAD_ARITHMETIC_TRIPS; ++index) {
        uint32_t slot = index & (OVERHEAD_MEMORY_WORDS - 1u);
        uint64_t next = ARITHMETIC_STEP(value + overhead_state.direct_words[slot], index);
        overhead_state.direct_words[slot] = next;
        value ^= next;
    }
    overhead_state.result = value;
    return 0;
}

SEC("syscall")
int overhead_capsule_combined(void) {
    overhead_state.capsule = capsule_call((uint64_t*)&overhead_state.result, managed_combined, OVERHEAD_ARITHMETIC_TRIPS);
    return 0;
}

SEC("syscall")
int overhead_direct_pointer_chase(void) {
    uint32_t slot = 0;
    uint64_t value = 7;
    for (uint32_t index = 0; index < OVERHEAD_ARITHMETIC_TRIPS; ++index) {
        slot = overhead_state.direct_nodes[slot].next;
        uint64_t next = ARITHMETIC_STEP(value + overhead_state.direct_nodes[slot].value, index);
        overhead_state.direct_nodes[slot].value = next;
        value ^= next;
    }
    overhead_state.result = value;
    return 0;
}

SEC("syscall")
int overhead_capsule_pointer_chase(void) {
    overhead_state.capsule = capsule_call((uint64_t*)&overhead_state.result, managed_pointer_chase, OVERHEAD_ARITHMETIC_TRIPS);
    return 0;
}

char _license[] SEC("license") = "GPL";
