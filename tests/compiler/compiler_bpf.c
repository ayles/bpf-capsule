// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <setjmp.h>

#include "bpf_capsule.h"
#include "compiler_test.h"

volatile struct compiler_test_result compiler_result SEC(".data.ctres");
volatile int compiler_input SEC(".data.ctin") = 18;
volatile unsigned int compiler_vla_count SEC(".data.ctin") = 4096;
volatile double compiler_fp_input SEC(".data.ctfp") = 9.0;
volatile struct compiler_guard_result compiler_guards SEC(".data.ctguard");
volatile struct compiler_fiber_result compiler_fibers SEC(".data.ctfiber");
volatile struct compiler_allocator_result compiler_allocator SEC(".data.ctalloc");
volatile struct compiler_return_result compiler_returns SEC(".data.ctreturn");
uint64_t compiler_main_continuation SEC(".data.ctstate") = BPF_CAPSULE_NO_CONTINUATION;
uint64_t compiler_jump_continuation SEC(".data.ctstate") = BPF_CAPSULE_NO_CONTINUATION;
volatile uint64_t compiler_fiber_spin SEC(".data.ctstate");
volatile unsigned int compiler_native_atomic32 SEC(".data.ctatomic") = 11;
volatile uint64_t compiler_native_atomic64 SEC(".data.ctatomic") = 101;

extern void* malloc(unsigned long size);
extern void* memalign(unsigned long alignment, unsigned long size);
extern void* realloc(void* pointer, unsigned long size);
extern void free(void* pointer);
extern unsigned long malloc_usable_size(void* pointer);

// Giving the declaration an LLVM intrinsic name makes this a direct test of
// the soft-float intrinsic-to-libm lowering, not of a C library shim.
extern double compiler_sqrt_intrinsic(double) __asm__("llvm.sqrt.f64");

static const double compiler_fp_table[] = {1.25, -2.5, 3.75, 8.0};
static unsigned char compiler_capsule_atomic8;
static unsigned short compiler_capsule_atomic16;
static unsigned int compiler_capsule_atomic32;
static uint64_t compiler_capsule_atomic64;

static struct compiler_return_value compiler_return_value(unsigned int seed) {
    struct compiler_return_value value = {
        .wide = 0x9e3779b97f4a7c15ull ^ seed,
        .word = 0x6a09e667u + seed * 17u,
        .half = (unsigned short)(0xbb67u ^ seed),
    };
    for (unsigned int index = 0; index < sizeof(value.bytes); ++index) {
        value.bytes[index] = (unsigned char)(seed + index * 13u);
    }
    return value;
}

static struct compiler_return_value compiler_return_immediate(unsigned int seed) {
    return compiler_return_value(seed);
}

__attribute__((noinline)) static unsigned int compiler_return_step(unsigned int value) {
    return value * 33u + 17u;
}

static struct compiler_return_value compiler_return_suspended(unsigned int seed) {
    unsigned int (*volatile step)(unsigned int) = compiler_return_step;
    unsigned int value = seed;
    for (unsigned int index = 0; index < 512; ++index) {
        value = step(value);
    }
    return compiler_return_value(value);
}

static int compiler_return_equal(volatile const struct compiler_return_value* left, const struct compiler_return_value* right) {
    if (left->wide != right->wide || left->word != right->word || left->half != right->half) {
        return 0;
    }
    for (unsigned int index = 0; index < sizeof(left->bytes); ++index) {
        if (left->bytes[index] != right->bytes[index]) {
            return 0;
        }
    }
    return 1;
}

static int fib(int n) {
    return n < 2 ? n : fib(n - 1) + fib(n - 2);
}

static int sum7(int a, int b, int c, int d, int e, int f, int g) {
    return a + b + c + d + e + f + g;
}

__attribute__((noinline, noreturn)) static void compiler_jump_leaf(jmp_buf env, int value) {
    longjmp(env, value);
}

__attribute__((noinline)) static int compiler_jump_once(int value) {
    jmp_buf env;
    int result = setjmp(env);
    if (!result) {
        compiler_jump_leaf(env, value);
    }
    return result;
}

static int compiler_jump_body(void) {
    return compiler_jump_once(37) * 10 + compiler_jump_once(0);
}

// InstCombine recognizes this source-shaped multiply/divide-back test as
// llvm.umul.with.overflow.i64 during default<O2>. That happens after the first
// bpf-expand-i128 run, so the second run must expand the intrinsic before the
// BPF backend can request an unavailable 128-bit multiplication libcall.
static int multiply_overflow(uint64_t left, uint64_t right) {
    uint64_t product = left * right;
    return left && product / left != right;
}

struct aggregate {
    uint64_t value;
    int64_t tag;
};

__attribute__((noinline)) static struct aggregate make_aggregate(uint64_t value, int64_t tag) {
    struct aggregate result = {value, tag};
    return result;
}

__attribute__((noinline)) static struct aggregate pass_aggregate(struct aggregate value) {
    return make_aggregate(value.value + 1, value.tag + 2);
}

// A tail replacement preserves the upper frame boundary, not its base: the
// replacement may need a completely different amount of stack. Results must
// therefore remain anchored immediately below that boundary. QuickJS exposed
// both directions when the first downward-stack implementation left results
// at the moving frame base.
__attribute__((noinline)) static int tail_large_result(int value) {
    volatile unsigned char padding[513];
    padding[0] = (unsigned char)(value ^ 0x5a);
    padding[512] = (unsigned char)(value + 7);
    return value + padding[0] + padding[512];
}

__attribute__((noinline)) static int tail_small_to_large(int value) {
    return tail_large_result(value);
}

__attribute__((noinline)) static int tail_small_result(int value) {
    return value * 7 - 3;
}

__attribute__((noinline)) static int tail_large_to_small(int value) {
    volatile unsigned char padding[321];
    padding[0] = (unsigned char)(value + 11);
    padding[320] = (unsigned char)(value ^ 0xa5);
    return tail_small_result(value + padding[0] - padding[320]);
}

typedef int (*tail_case)(int);
static tail_case volatile tail_cases[] = {
    tail_small_to_large,
    tail_large_to_small,
    tail_large_result,
    tail_small_result,
};

static unsigned char pool[4096];
static unsigned long pool_offset;

// Both objects are zero-initialized and therefore live in the dynamically
// allocated sparse arena. This is the reduced form of PureDOOM's
// `ds_p - drawsegs` range check.
struct sparse_item {
    uint64_t words[8];
};
static struct sparse_item sparse_items[64];
static struct sparse_item* sparse_cursor;
static struct sparse_item* sparse_initialized_cursor = &sparse_items[7];

#define COPY_BYTES 256000ul
#define COPY_MAP_SIZE (1ul << 18)
static unsigned char copy_storage[COPY_BYTES + 32];
unsigned char compiler_copy_output[COPY_MAP_SIZE] SEC(".bss.ctcopy");

static uint64_t copy_word(unsigned long offset) {
    return 0x9e3779b97f4a7c15ull ^ (uint64_t)offset * 0xd6e8feb86659fd93ull;
}

__attribute__((noinline)) static void compiler_memset(void* pointer, int value, int count) {
    unsigned char* bytes = pointer;
    for (int i = 0; i < count; ++i) {
        bytes[i] = (unsigned char)value;
    }
}

__attribute__((noinline)) static void copy_to_sectioned_output(const unsigned char* source) {
    for (unsigned long i = 0; i < COPY_BYTES; i += 8) {
        uint64_t value = *(const uint64_t*)(source + i);
        unsigned long visible = i;
        asm volatile("" : "+r"(visible));
        *(uint64_t*)(compiler_copy_output + (visible & (COPY_MAP_SIZE - 8))) = value;
    }
}

static void* allocate(unsigned items, unsigned size) {
    unsigned long bytes = ((unsigned long)items * size + 7) & ~7ul;
    if (pool_offset + bytes > sizeof(pool)) {
        return 0;
    }
    void* result = pool + pool_offset;
    pool_offset += bytes;
    return result;
}

struct nested_state {
    void* allocation;
    unsigned char scratch[64];
};

typedef void* (*allocator)(unsigned, unsigned);

__attribute__((noinline)) static int initialize_indirect(struct nested_state* state, allocator alloc) {
    state->allocation = alloc(1, sizeof(*state));
    return state->allocation ? 0 : -1;
}

// The nested call returns before a long loop crosses several continuation
// boundaries. The caller must resume the loop rather than consume a stale
// return slot as its own result.
__attribute__((noinline)) static int nested_then_long_loop(struct nested_state* state) {
    if (initialize_indirect(state, allocate)) {
        return -1;
    }
    for (unsigned i = 0; i < 60000; i++) {
        state->scratch[i & 63] = (unsigned char)i;
    }
    return 0;
}

// A continuation backedge must update loop PHIs as one parallel assignment.
// Demoting two pointer PHIs one at a time used to make the second assignment
// observe the already-updated first slot. PureDOOM's masked drawseg loop
// exposed the same shape at much larger scale.
struct parallel_phi_item {
    unsigned value;
};

typedef unsigned (*parallel_phi_reader)(struct parallel_phi_item*);

__attribute__((noinline)) static unsigned parallel_phi_read(struct parallel_phi_item* item) {
    return item->value;
}

__attribute__((noinline)) static unsigned
parallel_phi_loop(struct parallel_phi_item* left, struct parallel_phi_item* right, unsigned count, parallel_phi_reader read) {
    unsigned sum = 0;
    while (count--) {
        // The indirect managed calls force the two pointer PHIs to survive a
        // continuation. The backedge swaps them as one parallel assignment.
        sum += read(left) * 10 + read(right);
        struct parallel_phi_item* temporary = left;
        left = right;
        right = temporary;
    }
    return sum;
}

static void compiler_test_body(void) {
    uint64_t failures = 0;
    uint64_t checksum = 0;

    int n = compiler_input;
    int recursion = fib(n);
    if (recursion != 2584) {
        failures |= 1;
    }
    checksum = checksum * 131 + (unsigned)recursion;

    int (*volatile indirect)(int, int, int, int, int, int, int) = sum7;
    int many_args = indirect(n, 2, 3, 4, 5, 6, 7);
    if (many_args != 45) {
        failures |= 2;
    }
    checksum = checksum * 131 + (unsigned)many_args;

    uint64_t overflow_left = (uint64_t)(unsigned)n << 60;
    if (!multiply_overflow(overflow_left, 17)) {
        failures |= 8192;
    }
    checksum = checksum * 131 + multiply_overflow((unsigned)n, 17);

    int small_to_large = tail_cases[0](n);
    int large_to_small = tail_cases[1](n);
    if (small_to_large != 115 || large_to_small != -955) {
        failures |= 4096;
    }
    checksum = checksum * 131 + (unsigned)small_to_large;
    checksum = checksum * 131 + (unsigned)large_to_small;

    for (unsigned i = 0; i < 8; i++) {
        struct aggregate input = make_aggregate(i, (int64_t)i * 100);
        struct aggregate output = pass_aggregate(input);
        if (output.value != i + 1 || output.tag != (int64_t)i * 100 + 2) {
            failures |= 4;
        }
        checksum = checksum * 131 + output.value;
        checksum = checksum * 131 + (uint64_t)output.tag;
    }

    pool_offset = 0;
    struct nested_state state = {0};
    allocator volatile alloc = allocate;
    if (initialize_indirect(&state, alloc) || !state.allocation) {
        failures |= 8;
    }
    pool_offset = 0;
    state = (struct nested_state){0};
    if (nested_then_long_loop(&state) || state.scratch[63] != 63) {
        failures |= 16;
    }
    checksum = checksum * 131 + state.scratch[63];

    // Clang emits literal FP tables as ConstantDataArray. The soft-float pass
    // must preserve every element while changing its representation to bits.
    double selected = compiler_fp_table[(unsigned)n & 3];
    if (selected != 3.75) {
        failures |= 32;
    }
    checksum = checksum * 131 + (uint64_t)selected;

    sparse_cursor = sparse_items + 34;
    long sparse_difference = sparse_cursor - sparse_items;
    if (sparse_difference != 34) {
        failures |= 64;
    }
    compiler_result.sparse_pointer_difference = sparse_difference;
    checksum = checksum * 131 + (uint64_t)sparse_difference;

    // No source-level initialization hook is called. The arena entry prologue
    // must install this pointer fixup; the map tier must encode the equivalent
    // integer offset directly in its ELF data image.
    long initialized_difference = sparse_initialized_cursor - sparse_items;
    if (initialized_difference != 7) {
        failures |= 128;
    }
    compiler_result.initialized_pointer_difference = initialized_difference;
    checksum = checksum * 131 + (uint64_t)initialized_difference;

    // A large arena-pointer -> explicitly sectioned map copy is the reduced
    // form used to rule out Doom's framebuffer export during diagnosis.
    // Retain it as a generic loop-boundary and address-space regression.
    unsigned char* copy_source = copy_storage + 16;
    for (unsigned long i = 0; i < COPY_BYTES; i += 8) {
        *(uint64_t*)(copy_source + i) = copy_word(i);
    }
    copy_to_sectioned_output(copy_source);
    uint64_t copy_failures = 0;
    uint64_t first_copy_failure = COPY_BYTES;
    for (unsigned long i = 0; i < COPY_BYTES; i += 8) {
        if (*(uint64_t*)(compiler_copy_output + i) != copy_word(i)) {
            if (!copy_failures) {
                first_copy_failure = i;
            }
            ++copy_failures;
        }
    }
    if (copy_failures) {
        failures |= 256;
    }
    compiler_result.copy_failures = copy_failures;
    compiler_result.first_copy_failure = first_copy_failure;
    checksum = checksum * 131 + copy_failures;

    compiler_memset(copy_source, 0, COPY_BYTES);
    uint64_t memset_failures = 0;
    uint64_t first_memset_failure = COPY_BYTES;
    for (unsigned long i = 0; i < COPY_BYTES; ++i) {
        if (copy_source[i]) {
            if (!memset_failures) {
                first_memset_failure = i;
            }
            ++memset_failures;
        }
    }
    if (memset_failures) {
        failures |= 512;
    }
    compiler_result.memset_failures = memset_failures;
    compiler_result.first_memset_failure = first_memset_failure;
    checksum = checksum * 131 + memset_failures;

    struct parallel_phi_item phi_items[2] = {{1}, {2}};
    unsigned (*volatile phi_loop)(struct parallel_phi_item*, struct parallel_phi_item*, unsigned, parallel_phi_reader) = parallel_phi_loop;
    parallel_phi_reader volatile phi_read = parallel_phi_read;
    unsigned parallel_phi_sum = phi_loop(&phi_items[0], &phi_items[1], (unsigned)n, phi_read);
    if (parallel_phi_sum != 297) {
        failures |= 1024;
    }
    compiler_result.parallel_phi_sum = parallel_phi_sum;
    checksum = checksum * 131 + parallel_phi_sum;

    // Naturally aligned relaxed loads and stores are the exact Capsule
    // atomic subset. Exercise every supported width after ordinary globals
    // have been routed through either the arena or the 5.15 map backend.
    __atomic_store_n(&compiler_capsule_atomic8, 0x12, __ATOMIC_RELAXED);
    __atomic_store_n(&compiler_capsule_atomic16, 0x3456, __ATOMIC_RELAXED);
    __atomic_store_n(&compiler_capsule_atomic32, 0x789abcde, __ATOMIC_RELAXED);
    __atomic_store_n(&compiler_capsule_atomic64, 0x0123456789abcdefull, __ATOMIC_RELAXED);
    if (__atomic_load_n(&compiler_capsule_atomic8, __ATOMIC_RELAXED) != 0x12 || __atomic_load_n(&compiler_capsule_atomic16, __ATOMIC_RELAXED) != 0x3456 ||
        __atomic_load_n(&compiler_capsule_atomic32, __ATOMIC_RELAXED) != 0x789abcde ||
        __atomic_load_n(&compiler_capsule_atomic64, __ATOMIC_RELAXED) != 0x0123456789abcdefull) {
        failures |= 2048;
    }
    checksum = checksum * 131 + __atomic_load_n(&compiler_capsule_atomic64, __ATOMIC_RELAXED);

    compiler_result.failures = failures;
    compiler_result.checksum = checksum;
}

SEC("syscall")
int compiler_test_run(void) {
    struct capsule_result result = capsule_call_void(compiler_test_body);
    compiler_main_continuation = result.continuation;
    compiler_result.pending = result.status == CAPSULE_PENDING;
    compiler_result.code = result.code;
    return 0;
}

// Native BPF keeps verifier-visible pointers and therefore uses the real BPF
// atomic ISA. The 5.15 arm64 profile supports non-fetching ADD for both word
// widths. The 6.9 profile additionally has fetch ops, exchange and cmpxchg.
SEC("syscall")
int compiler_native_atomic_run(void) {
    uint64_t failures = 0;
    (void)__atomic_fetch_add(&compiler_native_atomic32, 5, __ATOMIC_RELAXED);
    (void)__atomic_fetch_add(&compiler_native_atomic64, 7, __ATOMIC_RELAXED);
    if (__atomic_load_n(&compiler_native_atomic32, __ATOMIC_RELAXED) != 16) {
        failures |= 1;
    }
    if (__atomic_load_n(&compiler_native_atomic64, __ATOMIC_RELAXED) != 108) {
        failures |= 2;
    }

#if BPF_CAPSULE_FEATURE_FULL_ATOMICS
    unsigned int old32 = __atomic_fetch_xor(&compiler_native_atomic32, 0x30, __ATOMIC_SEQ_CST);
    uint64_t old64 = __atomic_exchange_n(&compiler_native_atomic64, 0x123456789abcdef0ull, __ATOMIC_SEQ_CST);
    unsigned int expected = 0x20;
    int exchanged = __atomic_compare_exchange_n(&compiler_native_atomic32, &expected, 0x55, 0, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST);
    if (old32 != 16 || old64 != 108 || !exchanged || expected != 0x20) {
        failures |= 4;
    }
    if (__atomic_load_n(&compiler_native_atomic32, __ATOMIC_RELAXED) != 0x55) {
        failures |= 8;
    }
    if (__atomic_load_n(&compiler_native_atomic64, __ATOMIC_RELAXED) != 0x123456789abcdef0ull) {
        failures |= 16;
    }
#endif

    compiler_result.native_atomic_failures = failures;
    return 0;
}

SEC("syscall")
int compiler_return_immediate_run(void) {
    compiler_returns.immediate_capsule = capsule_call(&compiler_returns.immediate, compiler_return_immediate, 0x1234u);
    return 0;
}

SEC("syscall")
int compiler_return_suspended_run(void) {
    const struct compiler_return_value sentinel = {
        .wide = 0xffffffffffffffffull,
        .word = 0xffffffffu,
        .half = 0xffffu,
        .bytes = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
    };
    compiler_returns.suspended = sentinel;
    compiler_returns.suspended_capsule = capsule_call(&compiler_returns.suspended, compiler_return_suspended, 0x5678u);
    compiler_returns.pending_output_unchanged = compiler_return_equal(&compiler_returns.suspended, &sentinel);
    return 0;
}

SEC("syscall")
int compiler_return_suspended_drain(void) {
    compiler_returns.suspended_capsule = capsule_continue(&compiler_returns.suspended, compiler_returns.suspended_capsule.continuation);
    return 0;
}

SEC("syscall")
int compiler_test_drain(void) {
    uint64_t continuation = compiler_main_continuation;
    struct capsule_result result = capsule_continue_void(continuation);
    compiler_main_continuation = result.continuation;
    compiler_result.pending = result.status == CAPSULE_PENDING;
    compiler_result.code = result.code;
    return 0;
}

static void compiler_fp_intrinsic_body(void) {
    compiler_guards.intrinsic_after = 0;
    double value = compiler_sqrt_intrinsic(compiler_fp_input);
    compiler_guards.intrinsic_value = (uint64_t)value;
    compiler_guards.intrinsic_after = 1;
}

uint64_t compiler_fp_continuation SEC(".data.ctstate") = BPF_CAPSULE_NO_CONTINUATION;

SEC("syscall")
int compiler_fp_intrinsic_run(void) {
    // The intrinsic lowers to the linked libm sqrt — a real managed call
    // chain, which this suite's tiny drive budget suspends. The host re-runs
    // while the result stays pending, like the other continuation flows.
    struct capsule_result result;
    if (compiler_fp_continuation == BPF_CAPSULE_NO_CONTINUATION) {
        result = capsule_call_void(compiler_fp_intrinsic_body);
    } else {
        result = capsule_continue_void(compiler_fp_continuation);
    }
    compiler_fp_continuation = result.status == CAPSULE_PENDING ? result.continuation : BPF_CAPSULE_NO_CONTINUATION;
    compiler_guards.intrinsic_status = result.status;
    compiler_guards.intrinsic_code = result.code;
    return 0;
}

static void compiler_vla_guard_body(void) {
    compiler_guards.vla_before = 1;
    compiler_guards.vla_after = 0;
    unsigned int count = compiler_vla_count;
    volatile unsigned char bytes[count];
    bytes[0] = 0x5a;
    bytes[count - 1] = 0xa5;
    compiler_guards.vla_after = (bytes[0] == 0x5a && bytes[count - 1] == 0xa5) ? 1 : 2;
}

__attribute__((noinline)) static void compiler_fiber_touch_leaf(volatile unsigned char* byte) {
    *byte = *byte;
}

static void compiler_fiber_body(unsigned int value, unsigned int other) {
    volatile unsigned char scratch[64] = {0};
    scratch[63] = (unsigned char)value;
    // An indirect managed call necessarily crosses the software dispatcher.
    // The integration target deliberately drives four steps per entry, so this
    // leaves the addressable local live across at least one continuation.
    void (*volatile touch)(volatile unsigned char*) = compiler_fiber_touch_leaf;
    for (unsigned int i = 0; i < 200; ++i) {
        touch(&scratch[63]);
    }
    if (other) {
        compiler_fibers.other_value = scratch[63];
    } else {
        compiler_fibers.resumed_value = scratch[63];
    }
}

static unsigned int compiler_fiber_short_body(void) {
    compiler_fiber_spin = 0x51;
    return capsule_fiber_index();
}

static void compiler_exit_body(void) {
    compiler_guards.exit_after = 0;
    // capsule_exit masks its argument with 0xff exactly as POSIX observes an
    // exit status; -37 deliberately pins that contract by observing 219.
    capsule_exit(-37);
    compiler_guards.exit_after = 1;
}

static void compiler_trap_body(void) {
    compiler_guards.trap_after = 0;
    __builtin_trap();
    compiler_guards.trap_after = 1;
}

SEC("syscall")
int compiler_exit_contract_run(void) {
    // Keep one of the two configured fibers leased. The call after exit can
    // succeed only if the exiting call reclaimed the other slot.
    struct capsule_result held = capsule_call_void(compiler_fiber_body, 0x73, 0);
    struct capsule_result exited = capsule_call_void(compiler_exit_body);
    unsigned int reused_fiber = 0;
    struct capsule_result reused = capsule_call(&reused_fiber, compiler_fiber_short_body);
    struct capsule_result reset = capsule_reset(held.continuation);

    compiler_guards.exit_held_status = held.status;
    compiler_guards.exit_status = exited.status;
    compiler_guards.exit_code = exited.code;
    compiler_guards.exit_reuse_status = reused.status;
    compiler_guards.exit_reset_status = reset.status;
    return 0;
}

SEC("syscall")
int compiler_trap_contract_run(void) {
    struct capsule_result trapped = capsule_call_void(compiler_trap_body);
    compiler_guards.trap_status = trapped.status;
    compiler_guards.trap_code = trapped.code;
    return 0;
}

SEC("syscall")
int compiler_jump_run(void) {
    struct capsule_result result = compiler_jump_continuation == BPF_CAPSULE_NO_CONTINUATION
        ? capsule_call(&compiler_guards.jump_value, compiler_jump_body)
        : capsule_continue(&compiler_guards.jump_value, compiler_jump_continuation);
    compiler_jump_continuation = result.status == CAPSULE_PENDING ? result.continuation : BPF_CAPSULE_NO_CONTINUATION;
    compiler_guards.jump_capsule = result;
    return 0;
}

// A Capsule boundary is allowed in an ordinary native helper, not just
// directly in an ELF entry. Keep two source wrappers out of line to prove that
// stackify recursively flattens the boundary-owning chain and does not leave
// extra BPF frames above the trampoline's fixed native-stack budget.
__attribute__((noinline)) static struct capsule_result compiler_nested_capsule_call_inner(void) {
    unsigned int fiber = 0;
    return capsule_call(&fiber, compiler_fiber_short_body);
}

__attribute__((noinline)) static struct capsule_result compiler_nested_capsule_call(void) {
    return compiler_nested_capsule_call_inner();
}

SEC("syscall")
int compiler_nested_capsule_run(void) {
    struct capsule_result result = compiler_nested_capsule_call();
    return result.status == CAPSULE_OK ? 0 : 1;
}

SEC("syscall")
int compiler_fiber_start(void) {
    struct capsule_result first = capsule_call_void(compiler_fiber_body, 0x5a, 0);
    struct capsule_result second = capsule_call_void(compiler_fiber_body, 0xa5, 1);
    unsigned int exhausted_fiber = 0;
    struct capsule_result exhausted = capsule_call(&exhausted_fiber, compiler_fiber_short_body);
    compiler_fibers.start_status = first.status;
    compiler_fibers.second_start_status = second.status;
    compiler_fibers.resume_status = first.status;
    compiler_fibers.other_status = second.status;
    compiler_fibers.exhausted_status = exhausted.status;
    compiler_fibers.exhausted_code = exhausted.code;
    compiler_fibers.first_fiber = first.continuation;
    compiler_fibers.second_fiber = second.continuation;
    compiler_fibers.paused_pending = first.status == CAPSULE_PENDING;
    compiler_fibers.paused_code = first.code;
    return 0;
}

SEC("syscall")
int compiler_fiber_other(void) {
    uint64_t fiber = compiler_fibers.second_fiber;
    struct capsule_result result = capsule_continue_void(fiber);
    compiler_fibers.other_status = result.status;
    compiler_fibers.other_code = result.code;
    if (result.status == CAPSULE_PENDING || result.status == CAPSULE_YIELD) {
        compiler_fibers.second_fiber = result.continuation;
    }
    return 0;
}

SEC("syscall")
int compiler_fiber_resume(void) {
    uint64_t first = compiler_fibers.first_fiber;
    struct capsule_result resumed = capsule_continue_void(first);
    compiler_fibers.resume_status = resumed.status;
    compiler_fibers.resume_code = resumed.code;
    if (resumed.status == CAPSULE_PENDING || resumed.status == CAPSULE_YIELD) {
        compiler_fibers.first_fiber = resumed.continuation;
    }

    if (resumed.status != CAPSULE_PENDING) {
        struct capsule_result pending = capsule_call_void(compiler_fiber_body, 0x33, 0);
        struct capsule_result reset = capsule_reset(pending.continuation);
        compiler_fibers.reset_status = reset.status;
        compiler_fibers.reset_fiber = pending.continuation;
        unsigned int after_reset_fiber = ~0u;
        struct capsule_result after_reset = capsule_call(&after_reset_fiber, compiler_fiber_short_body);
        compiler_fibers.after_reset_status = after_reset.status;
        compiler_fibers.after_reset_fiber = after_reset_fiber;
    }
    return 0;
}

// Two userspace threads enter these roots simultaneously. They own distinct
// fibers but deliberately share the one freestanding TLSF heap. Every round
// keeps several differently sized blocks live, checks their contents across
// realloc, and frees in reverse order. This catches both duplicate allocation
// and partially-updated free-list metadata; a sequential allocator test does
// neither.
static void compiler_allocator_body(unsigned int lane) {
    uint64_t failures = 0;
    uint64_t checksum = 0xcbf29ce484222325ull ^ lane;
    uint64_t operations = 0;

    for (unsigned int round = 0; round < 48; ++round) {
        unsigned char* blocks[6] = {0};
        unsigned int sizes[6] = {0};

        for (unsigned int slot = 0; slot < 6; ++slot) {
            unsigned int size = ((round * 97u + slot * 53u + lane * 29u) & 511u) + 16u;
            sizes[slot] = size;
            blocks[slot] = slot == 0 ? memalign(64, size) : malloc(size);
            operations++;
            if (!blocks[slot]) {
                failures |= 1ull << slot;
                continue;
            }
            if (slot == 0 && ((unsigned long)blocks[slot] & 63u)) {
                failures |= 1ull << 8;
            }
            if (malloc_usable_size(blocks[slot]) < size) {
                failures |= 1ull << 9;
            }
            for (unsigned int i = 0; i < size; ++i) {
                unsigned char value = (unsigned char)(lane * 67u + round * 13u + slot * 7u + i);
                blocks[slot][i] = value;
            }
        }

        for (unsigned int slot = 0; slot < 6; ++slot) {
            if (!blocks[slot]) {
                continue;
            }
            for (unsigned int i = 0; i < sizes[slot]; ++i) {
                unsigned char expected = (unsigned char)(lane * 67u + round * 13u + slot * 7u + i);
                unsigned char value = blocks[slot][i];
                if (value != expected) {
                    failures |= 1ull << 16;
                }
                checksum = (checksum ^ value) * 0x100000001b3ull;
            }
        }

        if (blocks[2]) {
            unsigned int old_size = sizes[2];
            unsigned int new_size = old_size + 127u;
            unsigned char* grown = realloc(blocks[2], new_size);
            operations++;
            if (!grown) {
                failures |= 1ull << 17;
            } else {
                blocks[2] = grown;
                sizes[2] = new_size;
                for (unsigned int i = 0; i < old_size; ++i) {
                    unsigned char expected = (unsigned char)(lane * 67u + round * 13u + 14u + i);
                    if (grown[i] != expected) {
                        failures |= 1ull << 18;
                    }
                }
                for (unsigned int i = old_size; i < new_size; ++i) {
                    grown[i] = (unsigned char)(0xa5u ^ lane ^ round ^ i);
                }
            }
        }

        for (unsigned int slot = 6; slot-- > 0;) {
            if (blocks[slot]) {
                free(blocks[slot]);
                operations++;
            }
        }
    }

    compiler_allocator.failures[lane] = failures;
    compiler_allocator.checksum[lane] = checksum;
    compiler_allocator.operations[lane] = operations;
}

SEC("syscall")
int compiler_allocator_run0(void) {
    struct capsule_result result = capsule_call_void(compiler_allocator_body, 0);
    compiler_allocator.first_fiber[0] = result.continuation;
    compiler_allocator.capsule[0] = result;
    return 0;
}

SEC("syscall")
int compiler_allocator_run1(void) {
    struct capsule_result result = capsule_call_void(compiler_allocator_body, 1);
    compiler_allocator.first_fiber[1] = result.continuation;
    compiler_allocator.capsule[1] = result;
    return 0;
}

SEC("syscall")
int compiler_allocator_drain0(void) {
    struct capsule_result result = capsule_continue_void(compiler_allocator.capsule[0].continuation);
    compiler_allocator.capsule[0] = result;
    return 0;
}

SEC("syscall")
int compiler_allocator_drain1(void) {
    struct capsule_result result = capsule_continue_void(compiler_allocator.capsule[1].continuation);
    compiler_allocator.capsule[1] = result;
    return 0;
}

SEC("syscall")
int compiler_vla_guard_run(void) {
    struct capsule_result result = capsule_call_void(compiler_vla_guard_body);
    compiler_guards.vla_status = result.status;
    compiler_guards.vla_code = result.code;
    return 0;
}

char _license[] SEC("license") = "GPL";
