// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
// The Capsule runtime: maps, globals, the trampoline drivers, the fiber
// pool, and the machinery behind the capsule_call family declared in
// bpf_capsule.h. The build pipeline compiles this file into every object
// automatically — application code never includes or compiles it, and the
// whole-program llvm-link resolves the extern glue the public macros expand
// to.
//
// Reserved names. The runtime owns the maps `arena`, `bpf_heap_array`, and
// `bpf_capsule_*`, the
// program `bpf_capsule_init`, the ELF sections `.rodata.bpfconfig`,
// `.rodata.bpffix`, `.bss.bpfctrl`, `.data.bpfctrl`, and `.data.bpfrdy`,
// and every `__bpf_capsule_*` symbol. Do not declare, resize, or write
// these from application code.
//
//   BPF_CAPSULE_FEATURE_*
//                       target capabilities selected by the build. This
//                       source gates on features, never on kernel versions.
//   __arena             qualifier for objects the memory model relocates.
//
// A program supplies its own sectioned native entry points and crosses into a
// compiler-managed closure explicitly with capsule_call(). The memory pass
// inserts a once-only arena initialization prologue in every entry;
// application source calls no initialization mechanism itself.

#include "bpf_capsule.h"
#include "bpf_capsule_abi.h"
#include "bpf_capsule_arithmetic.h"
#include "bpf_capsule_names.h"

#include <linux/bpf.h>
#include <linux/errno.h>
#include <bpf/bpf_helpers.h>

#define __BPF_CAPSULE_FN_CLASS(class_name) __attribute__((annotate(class_name)))

#ifndef BPF_CAPSULE_FEATURE_ARENA
#define BPF_CAPSULE_FEATURE_ARENA 0
#endif

// bpf-capsule-ld checks this private build marker against --memory. CMake
// compiles the runtime before invoking the linker, so a direct caller must
// not be able to combine one backend's runtime with the other backend's pass.
const unsigned int __bpf_capsule_memory_backend = BPF_CAPSULE_FEATURE_ARENA;

// Heap capacity used when the host does not call bpf_capsule_configure()
// before load. The host-selected value replaces it; this default only sizes
// the object loaded by stock libbpf with no Capsule host code.
#ifndef BPF_CAPSULE_DEFAULT_HEAP_BYTES
#define BPF_CAPSULE_DEFAULT_HEAP_BYTES (4u * 1024u * 1024u)
#endif

// ---------------------------------------------------------------- memory
//
// With bpf_arena the kernel gives us a flat address space and does the bounds
// check in hardware, so an access is one instruction and `__arena` is a real
// address-space qualifier.
//
// Without it, the layout pass assigns every global an offset in a flat image
// and rewrites each access to reach it through the regions below. A pointer
// becomes an integer offset, `__arena` means nothing, and the pass either
// resolves an access's region at compile time (one mask, one add) or routes it
// through the accessors here.

#if BPF_CAPSULE_FEATURE_ARENA

struct {
    __uint(type, BPF_MAP_TYPE_ARENA);
    __uint(map_flags, BPF_F_MMAPABLE);
    // Compiler placeholder: the arena pass replaces this with the exact page
    // capacity required by initialized data plus sparse program storage.
    __uint(max_entries, 1);
} BPF_CAPSULE_ARENA_MAP SEC(BPF_CAPSULE_SECTION_MAPS);

#ifndef __arena
#define __arena __attribute__((address_space(1)))
#endif

// LLVM's arena section contains only genuine initialized data. The compiler
// lays zero-filled globals after that compact prefix and this kfunc commits
// their pages before managed code starts. Doing it in the program turns an
// allocation failure into an ordinary return value; letting libbpf memcpy a
// many-megabyte zero image instead makes a failed mmap fault kill the loader.
extern void __arena* bpf_arena_alloc_pages(void* map, void __arena* address, uint32_t page_count, int numa_node, uint64_t flags) __ksym;
// Initialization state shared by the eager userspace hook and the entry
// fallback: 0 is uninitialized, 1 is owned by one initializer, and 2 is
// ready. The compiler emits the atomic transitions; keeping the word in an
// ordinary sectioned map makes them native BPF atomics rather than managed
// memory operations.
// The sparse allocation returned by bpf_arena_alloc_pages, verbatim (a full
// user virtual address), together with its 0 -> 1 -> 2 initialization
// state. The compiler adds per-object offsets to virtual_base; the result
// is already the pointer value, and only memory accesses convert it to
// address space 1.
struct __bpf_capsule_arena_control BPF_CAPSULE_ARENA_CONTROL_GLOBAL SEC(BPF_CAPSULE_SECTION_ARENA_CONTROL) = {0};

#else

#ifndef __arena
#define __arena
#endif

struct bpf_heap_array_value {
    uint8_t bytes[BPF_CAPSULE_MEMORY_REGION_SIZE + BPF_CAPSULE_MEMORY_REGION_PAD];
};
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(map_flags, BPF_F_MMAPABLE);
    __uint(max_entries, 1);
    __type(key, uint32_t);
    __type(value, struct bpf_heap_array_value);
} BPF_CAPSULE_HEAP_ARRAY_MAP SEC(BPF_CAPSULE_SECTION_MAPS);

// Set to 1 by bpf_capsule_initialize() once it has applied the
// baked-pointer fixups; capsule_call fails closed with BAD_PLAN before
// then. The arena tier gates through its own arena-control ready word and
// does not define this.
uint32_t __bpf_capsule_host_ready SEC(BPF_CAPSULE_SECTION_READY) = 0;

#endif

// ---------------------------------------------------------------- driver
//
// Managed code runs on a software call stack. The trampoline dispatches its
// top frame until it drains, using nested bounded global functions whose
// verification cost adds while their iteration counts multiply.
extern int __bpf_capsule_trampoline(uint32_t fiber);

struct __bpf_capsule_fiber_control BPF_CAPSULE_FIBER_CONTROLS_GLOBAL[BPF_CAPSULE_MAX_FIBERS] SEC(BPF_CAPSULE_SECTION_FIBER_CONTROLS);

const volatile struct __bpf_capsule_object_config BPF_CAPSULE_CONFIG_GLOBAL SEC(BPF_CAPSULE_SECTION_CONFIG) = {
    .heap_base = 0,
    .heap_bytes = BPF_CAPSULE_DEFAULT_HEAP_BYTES,
    .stack_base = 0,
    .memory_end = 0,
    .fiber_count = 1,
    // The linker owns the software-stack geometry and replaces this
    // placeholder before emitting the object.
    .stack_bytes_per_fiber = 0,
    .max_fibers = BPF_CAPSULE_MAX_FIBERS,
    .arena_image_pages = 0,
    .memory_backend = BPF_CAPSULE_FEATURE_ARENA ? BPF_CAPSULE_MEMORY_ARENA : BPF_CAPSULE_MEMORY_FIXED,
    .heap_reserved = 0,
    .abi_magic = BPF_CAPSULE_ABI_MAGIC,
    .abi_version = BPF_CAPSULE_ABI_VERSION,
    .memory_view_base = 0,
};

static __attribute__((always_inline)) uint32_t __bpf_capsule_fiber_count(void) {
    uint32_t count = bpf_capsule_config.fiber_count;
    return count >= 1 && count <= BPF_CAPSULE_MAX_FIBERS ? count : 0;
}

static __attribute__((always_inline)) struct __bpf_capsule_fiber_control* __bpf_capsule_fiber_control(uint32_t fiber);

// Publish a terminal event: the adjacent {status, code} pair is the whole
// protocol (see the record's comment in the private object ABI); every legal
// reader is ordered after these stores.
static __attribute__((always_inline)) void __bpf_capsule_stop(struct __bpf_capsule_fiber_control* control, int32_t code) {
    control->status = CAPSULE_EXITED;
    control->code = code;
}

// Arena targets recycle fibers through a LIFO stack after one-time issuance.
// Linux 5.15 rejects stack maps from the sleepable syscall programs used by
// BPF_PROG_TEST_RUN, so fixed-memory objects instead keep the exact active
// lease set in one preallocated hash.
#if BPF_CAPSULE_FEATURE_ARENA
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, BPF_CAPSULE_MAX_FIBERS);
    __type(key, uint32_t);
    __type(value, uint32_t);
} BPF_CAPSULE_ISSUED_FIBERS_MAP SEC(BPF_CAPSULE_SECTION_MAPS);

struct {
    __uint(type, BPF_MAP_TYPE_STACK);
    __uint(max_entries, BPF_CAPSULE_MAX_FIBERS);
    __type(value, uint32_t);
} BPF_CAPSULE_FREE_FIBERS_MAP SEC(BPF_CAPSULE_SECTION_MAPS);
#else
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, BPF_CAPSULE_MAX_FIBERS);
    __type(key, uint32_t);
    __type(value, uint64_t);
} BPF_CAPSULE_FIBER_LEASES_MAP SEC(BPF_CAPSULE_SECTION_MAPS);
#endif

// A continuation is consumed by claiming its complete generation-tagged
// token with BPF_NOEXIST. The claim exists only for the duration of one
// continue/reset entry; the helper operation is the cross-CPU linearization
// point, portable to every loader without relying on ISA atomics.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, BPF_CAPSULE_MAX_FIBERS);
    __type(key, uint64_t);
    __type(value, uint32_t);
} BPF_CAPSULE_CONTINUATION_CLAIMS_MAP SEC(BPF_CAPSULE_SECTION_MAPS);

// Generated by bpf-stackify: one dispatch of the top frame, non-zero once the
// stack is empty.
#if BPF_CAPSULE_FEATURE_ARENA
extern int __bpf_capsule_trampoline_step(uint32_t fiber, struct __bpf_capsule_fiber_control* fiber_control);
#else
extern struct bpf_heap_array_value* __bpf_capsule_stack_region(uint32_t fiber);
extern uint32_t __bpf_capsule_stack_offset(uint32_t fiber);
extern int __bpf_capsule_trampoline_step(uint32_t fiber, struct __bpf_capsule_fiber_control* fiber_control, void* stack_base);
#endif

// Borrowed verifier pointers cannot be stored in maps or arena memory. Context
// calls use a parallel typed driver that keeps the exact verifier provenance
// in BPF registers/native spills through every global subprogram call. The
// compiler supplies the step definition and selects this driver only for an
// explicit capsule_call_ctx/capsule_continue_ctx boundary.
#if BPF_CAPSULE_FEATURE_ARENA
extern int __bpf_capsule_trampoline_ctx_step(struct xdp_md* ctx, uint32_t fiber, struct __bpf_capsule_fiber_control* fiber_control);
#else
extern int __bpf_capsule_trampoline_ctx_step(struct xdp_md* ctx, uint32_t fiber, struct __bpf_capsule_fiber_control* fiber_control, void* stack_base);
#endif

// Iteration out of nothing but a bounded loop and a global function.
//
// A constant-trip loop is accepted, but the verifier simulates every iteration,
// so a loop big enough to run a frame would cost far more than the million
// instructions it is allowed. The way out is what the loop body is: a call to a
// *global* subprogram. Those are verified once, on their own, and the verifier
// does not descend into them from a call site -- so the body costs a call and a
// branch no matter how much work it does.
//
// Iterations therefore multiply while verification only adds. The entry
// program runs the nested driver, giving span * repeats dispatches for span +
// repeats worth of verification.
//
// No helper, no map, and nothing newer than function-by-function verification.
// One loop, and a short one, because of a second limit: the verifier tracks a
// jump history per path and gives up past BPF_COMPLEXITY_LIMIT_JMP_SEQ (8192).
// A loop of N iterations spends 2N of that budget, and nesting does not help --
// the history accumulates along the whole path, so nested loops in one function
// blow it just the same.
//
// Two levels of bounded loops in global subprograms give 4.2 million
// dispatches for a few thousand instructions of verification. Each level is
// checked once, standalone, and the verifier does not walk into a global
// subprogram at its call site. Runtime iterations therefore multiply while
// verification cost only adds. The construct needs no helper or iteration map
// and works on both supported kernel tiers.
//
// Measured alternatives, all rejected:
//   - bpf_for_each_map_elem (5.13+): same speed, but needs a 1<<20-element
//     array map -- 4 MiB bought purely to buy iterations.
//   - open-coded iterators (6.4+): the loop body is INLINE, so the verifier
//     walks it instead of checking it once, and zlib dies with "the sequence
//     of 8193 jumps is too complex". Being checked once, as a callback or a
//     global subprogram, is the whole trick; an inlined loop throws it away.
//   - bpf_loop (5.17+): calls its body through a function pointer once per
//     iteration, slower than a direct call.
// So this is the same construct on every kernel, which suits us: arena is
// then the only thing that varies by kernel version.
//
// Depth is bounded by stack, not by frames: the 512-byte limit is shared
// across the whole call chain, and three levels plus the step functions
// overruns it ("combined stack size of 7 calls is 544. Too large").
#ifndef BPF_CAPSULE_DRIVE_LEVEL
#define BPF_CAPSULE_DRIVE_LEVEL 2048
#endif
#if BPF_CAPSULE_FEATURE_ARENA
#define __BPF_CAPSULE_STACK_PARAMETER
#define __BPF_CAPSULE_STACK_ARGUMENT
#else
#define __BPF_CAPSULE_STACK_PARAMETER , void* stack_base
#define __BPF_CAPSULE_STACK_ARGUMENT , stack_base
#endif
#define __BPF_CAPSULE_CONTROL_PARAMETER , struct __bpf_capsule_fiber_control* fiber_control
#define __BPF_CAPSULE_CONTROL_ARGUMENT , fiber_control

#if !BPF_CAPSULE_FEATURE_ARENA
static __attribute__((always_inline)) void* __bpf_capsule_stack_base(uint32_t fiber, struct __bpf_capsule_fiber_control* control) {
    struct bpf_heap_array_value* region = __bpf_capsule_stack_region(fiber);
    if (!region) {
        __bpf_capsule_stop(control, CAPSULE_ERROR_MEMORY_FAULT);
        return 0;
    }
    return region->bytes + __bpf_capsule_stack_offset(fiber);
}
#endif

__BPF_CAPSULE_FN_CLASS("capsule.trampoline")
__attribute__((noinline)) int __bpf_capsule_trampoline_l1(uint32_t fiber __BPF_CAPSULE_CONTROL_PARAMETER __BPF_CAPSULE_STACK_PARAMETER) {
    for (int i = 0; i < BPF_CAPSULE_DRIVE_LEVEL; i++) {
        int status = __bpf_capsule_trampoline_step(fiber __BPF_CAPSULE_CONTROL_ARGUMENT __BPF_CAPSULE_STACK_ARGUMENT);
        if (status) {
            return status; // finished or aborted
        }
    }
    return 0;
}

__BPF_CAPSULE_FN_CLASS("capsule.trampoline") __attribute__((always_inline)) int __bpf_capsule_trampoline(uint32_t fiber) {
    struct __bpf_capsule_fiber_control* fiber_control = __bpf_capsule_fiber_control(fiber);
#if !BPF_CAPSULE_FEATURE_ARENA
    void* stack_base = __bpf_capsule_stack_base(fiber, fiber_control);
    if (!stack_base) {
        return 1;
    }
#endif
    for (int i = 0; i < BPF_CAPSULE_DRIVE_LEVEL; i++) {
        int status = __bpf_capsule_trampoline_l1(fiber __BPF_CAPSULE_CONTROL_ARGUMENT __BPF_CAPSULE_STACK_ARGUMENT);
        if (status) {
            return status;
        }
    }
    // A root return on the final bounded iteration leaves the completion
    // sentinel for the next step to clear. One final dispatch closes that
    // state; if work is genuinely pending it merely extends the compiled
    // maximum by one ordinary step.
    return __bpf_capsule_trampoline_step(fiber __BPF_CAPSULE_CONTROL_ARGUMENT __BPF_CAPSULE_STACK_ARGUMENT);
}

// Stackify decides whether the typed or scalar driver is needed only after
// the ordinary optimizer and global DCE have run. Pin the typed pair until
// that decision; Stackify removes the unused pair from the final object.
__BPF_CAPSULE_FN_CLASS("capsule.trampoline")
__attribute__((used, noinline)) int __bpf_capsule_trampoline_ctx_l1(
    struct xdp_md* ctx, uint32_t fiber __BPF_CAPSULE_CONTROL_PARAMETER __BPF_CAPSULE_STACK_PARAMETER) {
    for (int i = 0; i < BPF_CAPSULE_DRIVE_LEVEL; i++) {
        int status = __bpf_capsule_trampoline_ctx_step(ctx, fiber __BPF_CAPSULE_CONTROL_ARGUMENT __BPF_CAPSULE_STACK_ARGUMENT);
        if (status) {
            return status;
        }
    }
    return 0;
}

__BPF_CAPSULE_FN_CLASS("capsule.trampoline") __attribute__((used, always_inline)) int __bpf_capsule_trampoline_ctx(struct xdp_md* ctx, uint32_t fiber) {
    struct __bpf_capsule_fiber_control* fiber_control = __bpf_capsule_fiber_control(fiber);
#if !BPF_CAPSULE_FEATURE_ARENA
    void* stack_base = __bpf_capsule_stack_base(fiber, fiber_control);
    if (!stack_base) {
        return 1;
    }
#endif
    for (int i = 0; i < BPF_CAPSULE_DRIVE_LEVEL; i++) {
        int status = __bpf_capsule_trampoline_ctx_l1(ctx, fiber __BPF_CAPSULE_CONTROL_ARGUMENT __BPF_CAPSULE_STACK_ARGUMENT);
        if (status) {
            return status;
        }
    }
    return __bpf_capsule_trampoline_ctx_step(ctx, fiber __BPF_CAPSULE_CONTROL_ARGUMENT __BPF_CAPSULE_STACK_ARGUMENT);
}

#undef __BPF_CAPSULE_STACK_PARAMETER
#undef __BPF_CAPSULE_STACK_ARGUMENT
#undef __BPF_CAPSULE_CONTROL_PARAMETER
#undef __BPF_CAPSULE_CONTROL_ARGUMENT

// ---------------------------------------------------------------- control
//
// The driver checks this word between physical steps and stops without
// depending on a kernel exception mechanism. The managed software stack can
// then be reclaimed as one unit.
// Managed source uses this compiler accessor because its current fiber is a
// generated physical-step argument, not durable global state. Stackify removes
// every call before BPF emission. Native wrappers inspect a chosen fiber with
// the explicit accessors below.
// Internal users have already established ownership. Keep the fallback only
// to give old verifiers an obviously bounded data-map index; no public
// operation reaches it with an invalid ID.
static __attribute__((always_inline)) struct __bpf_capsule_fiber_control* __bpf_capsule_fiber_control(uint32_t fiber) {
    if (fiber >= BPF_CAPSULE_MAX_FIBERS) {
        fiber = 0;
    }
    return &bpf_capsule_fibers[fiber];
}

// --------------------------------------------------------------- fiber pool
//
// The control table has a compile-time verifier bound, while configure() backs
// stacks and lease maps only for the selected active count. Recycled IDs take
// the constant-time LIFO-stack path on the arena tier. During the one-time
// warm-up, starting at the current CPU normally claims the first candidate;
// BPF_NOEXIST remains the exact linearisation point if callers collide.
// Allocation is not public: only unfinished work exposes a leased fiber ID.
//
// Old verifiers simulate every iteration of a bounded loop even when the loop
// calls a separately verified global subprogram. A single loop over the fiber
// count therefore made storage capacity consume verifier complexity linearly.
// Keep the exact full-pool scan, but factor it into 16-attempt global chunks,
// 16-chunk global pages, and a tiny page loop. The kernel verifies each global
// body once, so 512 fibers cost 16 + 16 + 2 loop iterations rather than 512;
// runtime work and the BPF_NOEXIST linearisation semantics are unchanged.
#define BPF_CAPSULE_FIBER_SCAN_CHUNK 16u
#define BPF_CAPSULE_FIBER_SCAN_PAGE (BPF_CAPSULE_FIBER_SCAN_CHUNK * BPF_CAPSULE_FIBER_SCAN_CHUNK)
#define BPF_CAPSULE_CONTINUATION_FIBER_BITS 16u
#define BPF_CAPSULE_CONTINUATION_FIBER_MASK ((1ull << BPF_CAPSULE_CONTINUATION_FIBER_BITS) - 1u)
#define BPF_CAPSULE_CONTINUATION_GENERATION_MASK ((1ull << (64u - BPF_CAPSULE_CONTINUATION_FIBER_BITS)) - 1u)

enum __bpf_capsule_continuation_claim_result {
    __BPF_CAPSULE_CLAIM_MAP_CORRUPT = -2,
    __BPF_CAPSULE_CLAIM_INVALID = -1,
    __BPF_CAPSULE_CLAIM_STALE = 0,
    __BPF_CAPSULE_CLAIM_CONSUMED = 1,
};

static __attribute__((always_inline)) uint64_t __bpf_capsule_next_generation(uint64_t generation) {
    generation = (generation + 1u) & BPF_CAPSULE_CONTINUATION_GENERATION_MASK;
    return generation ? generation : 1u;
}

static __attribute__((always_inline)) uint64_t __bpf_capsule_continuation_value(uint32_t fiber, uint64_t generation) {
    return (generation << BPF_CAPSULE_CONTINUATION_FIBER_BITS) | fiber;
}

__attribute__((used, noinline)) uint64_t __bpf_capsule_make_continuation(uint32_t fiber) {
    if (fiber >= __bpf_capsule_fiber_count()) {
        return BPF_CAPSULE_NO_CONTINUATION;
    }
    return __bpf_capsule_continuation_value(fiber, __bpf_capsule_fiber_control(fiber)->generation);
}

__attribute__((used, noinline)) uint32_t __bpf_capsule_fiber_acquire_chunk(uint32_t start, uint32_t first) {
    uint32_t count = __bpf_capsule_fiber_count();
    if (start >= count || first >= count) {
        return __BPF_CAPSULE_NO_FIBER;
    }

#if BPF_CAPSULE_FEATURE_ARENA
    uint32_t one = 1;
#endif
#pragma clang loop unroll(disable)
    for (uint32_t local = 0; local < BPF_CAPSULE_FIBER_SCAN_CHUNK; ++local) {
        uint32_t attempt = first + local;
        if (attempt >= count) {
            return __BPF_CAPSULE_NO_FIBER;
        }
        uint32_t fiber = start + attempt;
        if (fiber >= count) {
            fiber -= count;
        }
#if BPF_CAPSULE_FEATURE_ARENA
        if (bpf_map_update_elem(&bpf_capsule_issued_fibers, &fiber, &one, BPF_NOEXIST) == 0) {
#else
        uint64_t generation = __bpf_capsule_next_generation(bpf_capsule_fibers[fiber].generation);
        if (bpf_map_update_elem(&bpf_capsule_fiber_leases, &fiber, &generation, BPF_NOEXIST) == 0) {
            bpf_capsule_fibers[fiber].generation = generation;
#endif
            return fiber;
        }
    }
    return __BPF_CAPSULE_NO_FIBER;
}

__attribute__((used, noinline)) uint32_t __bpf_capsule_fiber_acquire_page(uint32_t start, uint32_t first) {
    uint32_t count = __bpf_capsule_fiber_count();
    if (first >= count) {
        return __BPF_CAPSULE_NO_FIBER;
    }

#pragma clang loop unroll(disable)
    for (uint32_t chunk = 0; chunk < BPF_CAPSULE_FIBER_SCAN_CHUNK; ++chunk) {
        uint32_t offset = first + chunk * BPF_CAPSULE_FIBER_SCAN_CHUNK;
        if (offset >= count) {
            return __BPF_CAPSULE_NO_FIBER;
        }
        uint32_t fiber = __bpf_capsule_fiber_acquire_chunk(start, offset);
        if (fiber < count) {
            return fiber;
        }
    }
    return __BPF_CAPSULE_NO_FIBER;
}

static __attribute__((always_inline)) void __bpf_capsule_clear_fiber(struct __bpf_capsule_fiber_control* control) {
    control->status = CAPSULE_OK;
    control->code = 0;
    control->pc = 0;
    control->sp = 0;
    control->fp = 0;
    control->return_size = 0;
}

static __attribute__((always_inline)) void __bpf_capsule_prepare_fiber(uint32_t fiber) {
    struct __bpf_capsule_fiber_control* control = &bpf_capsule_fibers[fiber];
#if BPF_CAPSULE_FEATURE_ARENA
    control->generation = __bpf_capsule_next_generation(control->generation);
#endif
    __bpf_capsule_clear_fiber(control);
}

__attribute__((used, noinline)) uint32_t __bpf_capsule_fiber_acquire(void) {
    uint32_t count = __bpf_capsule_fiber_count();
    uint32_t fiber = __BPF_CAPSULE_NO_FIBER;
    if (!count) {
        return __BPF_CAPSULE_NO_FIBER;
    }
#if BPF_CAPSULE_FEATURE_ARENA
    if (bpf_map_pop_elem(&bpf_capsule_free_fibers, &fiber) == 0) {
        if (fiber >= count) {
            return __BPF_CAPSULE_NO_FIBER;
        }
        __bpf_capsule_prepare_fiber(fiber);
        return fiber;
    }
#endif
    uint32_t start = bpf_get_smp_processor_id() % count;
#pragma clang loop unroll(disable)
    for (uint32_t page = 0; page < (BPF_CAPSULE_MAX_FIBERS + BPF_CAPSULE_FIBER_SCAN_PAGE - 1) / BPF_CAPSULE_FIBER_SCAN_PAGE; ++page) {
        fiber = __bpf_capsule_fiber_acquire_page(start, page * BPF_CAPSULE_FIBER_SCAN_PAGE);
        if (fiber < count) {
            __bpf_capsule_prepare_fiber(fiber);
            return fiber;
        }
    }
    return __BPF_CAPSULE_NO_FIBER;
}

// Atomically consume one generation and install the generation returned by a
// subsequent PENDING/YIELD. Claiming the complete token is the single-consumer
// linearization point: duplicate continuations lose the BPF_NOEXIST insertion.
// Returns -2 for a claim-map invariant failure, -1 for a malformed token, 0
// for a stale token, and 1 when ownership was consumed. If ownership was
// consumed before claim cleanup failed, fiber_out is still published and the
// fiber is stopped with POOL_CORRUPT so the caller can reclaim it safely.
static __attribute__((always_inline)) int __bpf_capsule_consume_continuation(uint64_t continuation, uint32_t* fiber_out) {
    uint32_t fiber = (uint32_t)(continuation & BPF_CAPSULE_CONTINUATION_FIBER_MASK);
    uint64_t generation = continuation >> BPF_CAPSULE_CONTINUATION_FIBER_BITS;
    if (!generation || fiber >= __bpf_capsule_fiber_count()) {
        return __BPF_CAPSULE_CLAIM_INVALID;
    }
    uint32_t one = 1;
    long claim_error = bpf_map_update_elem(&bpf_capsule_continuation_claims, &continuation, &one, BPF_NOEXIST);
    if (claim_error != 0) {
        return claim_error == -EEXIST ? __BPF_CAPSULE_CLAIM_STALE : __BPF_CAPSULE_CLAIM_MAP_CORRUPT;
    }
    uint64_t next = __bpf_capsule_next_generation(generation);
    int consumed = 0;
#if BPF_CAPSULE_FEATURE_ARENA
    struct __bpf_capsule_fiber_control* control = &bpf_capsule_fibers[fiber];
    if ((control->pc || control->status == CAPSULE_EXITED) && control->generation == generation) {
        control->generation = next;
        consumed = 1;
    }
#else
    uint64_t* leased_generation = bpf_map_lookup_elem(&bpf_capsule_fiber_leases, &fiber);
    if (leased_generation && *leased_generation == generation) {
        *leased_generation = next;
        bpf_capsule_fibers[fiber].generation = next;
        consumed = 1;
    }
#endif
    if (consumed) {
        // Publish the validated owner before the fallible claim cleanup. A
        // cleanup failure must never leave the caller using NO_FIBER, whose
        // verifier-bounded fallback aliases fiber zero.
        *fiber_out = fiber;
    }
    if (bpf_map_delete_elem(&bpf_capsule_continuation_claims, &continuation) != 0) {
        // The entry was inserted by this invocation, so deletion failure is a
        // runtime-map invariant violation. Stop an otherwise valid owner
        // instead of continuing with a claim slot that can never be reused.
        if (consumed) {
            __bpf_capsule_stop(__bpf_capsule_fiber_control(fiber), CAPSULE_ERROR_POOL_CORRUPT);
        }
        return consumed ? __BPF_CAPSULE_CLAIM_CONSUMED : __BPF_CAPSULE_CLAIM_MAP_CORRUPT;
    }
    return consumed;
}

__attribute__((used, noinline)) int __bpf_capsule_fiber_release(uint32_t fiber) {
    if (fiber >= __bpf_capsule_fiber_count()) {
        return -1;
    }
#if BPF_CAPSULE_FEATURE_ARENA
    if (bpf_map_push_elem(&bpf_capsule_free_fibers, &fiber, 0) != 0) {
        // A full stack means a duplicate release or damaged pool. Keep the
        // slot visibly unavailable instead of risking concurrent reuse.
        __bpf_capsule_stop(&bpf_capsule_fibers[fiber], CAPSULE_ERROR_POOL_CORRUPT);
        return -1;
    }
#else
    if (bpf_map_delete_elem(&bpf_capsule_fiber_leases, &fiber) != 0) {
        __bpf_capsule_stop(&bpf_capsule_fibers[fiber], CAPSULE_ERROR_POOL_CORRUPT);
        return -1;
    }
#endif
    return 0;
}

static __attribute__((always_inline)) int __bpf_capsule_fiber_cancel(uint32_t fiber) {
    struct __bpf_capsule_fiber_control* control = __bpf_capsule_fiber_control(fiber);
    __bpf_capsule_clear_fiber(control);
    return __bpf_capsule_fiber_release(fiber);
}

__BPF_CAPSULE_FN_CLASS("capsule.entry-glue") __attribute__((always_inline)) void __bpf_capsule_finish_exited(struct capsule_result* result, uint32_t fiber) {
    result->code = __bpf_capsule_fiber_control(fiber)->code;
    result->status = CAPSULE_EXITED;
    if (__bpf_capsule_fiber_cancel(fiber)) {
        result->code = CAPSULE_ERROR_POOL_CORRUPT;
    }
    result->continuation = BPF_CAPSULE_NO_CONTINUATION;
}

extern void __bpf_capsule_copy_return(uint32_t fiber, void* output, uint64_t output_size, uint64_t output_alignment);

// Every load path funnels through the object, so the object itself proves the
// loader applied the complete configuration plan before any managed work
// runs. A half-applied plan (config blob stored but backing maps never
// resized, or vice versa) must fail loudly under any loader, not fault later.
int __bpf_capsule_plan_broken(void) {
    uint64_t heap_end = bpf_capsule_config.heap_base + bpf_capsule_config.heap_bytes;
    uint64_t stack_bytes = (uint64_t)bpf_capsule_config.stack_bytes_per_fiber * bpf_capsule_config.fiber_count;
    if (!bpf_capsule_config.fiber_count || bpf_capsule_config.fiber_count > BPF_CAPSULE_MAX_FIBERS || bpf_capsule_config.max_fibers != BPF_CAPSULE_MAX_FIBERS ||
        bpf_capsule_config.memory_backend != (BPF_CAPSULE_FEATURE_ARENA ? BPF_CAPSULE_MEMORY_ARENA : BPF_CAPSULE_MEMORY_FIXED) ||
        !bpf_capsule_config.stack_bytes_per_fiber || heap_end < bpf_capsule_config.heap_base || bpf_capsule_config.stack_base < heap_end ||
        bpf_capsule_config.memory_end != bpf_capsule_config.stack_base + stack_bytes || bpf_capsule_config.heap_reserved > bpf_capsule_config.heap_bytes ||
        bpf_capsule_config.abi_magic != BPF_CAPSULE_ABI_MAGIC || bpf_capsule_config.abi_version != BPF_CAPSULE_ABI_VERSION ||
        // bpf_capsule_configure() is mandatory on every tier: it reserves
        // the object's 4GiB-aligned memory window and bakes its base here
        // before the config freezes (on the arena tier the window becomes
        // the arena's pinned user_vm_start). Base zero means no
        // capsule-aware host prepared this object; refuse to run rather
        // than degrade to unbased offsets.
        !bpf_capsule_config.memory_view_base || (bpf_capsule_config.memory_view_base & 0xffffffffull)) {
        return 1;
    }
#if !BPF_CAPSULE_FEATURE_ARENA
    uint32_t last_region = (bpf_capsule_config.memory_end - 1u) >> BPF_CAPSULE_MEMORY_REGION_SHIFT;
    if (last_region >= BPF_CAPSULE_DIRECT_MEMORY_REGIONS) {
        uint32_t key = last_region - BPF_CAPSULE_DIRECT_MEMORY_REGIONS;
        if (!bpf_map_lookup_elem(&bpf_heap_array, &key)) {
            return 1;
        }
    }
    // bpf_capsule_initialize() has not applied the baked-pointer fixups
    // yet: function tokens and initializer pointers are still bare window
    // displacements. Fail closed, mirroring the arena tier's ready gate.
    if (!__bpf_capsule_host_ready) {
        return 1;
    }
#endif
    return 0;
}

static __attribute__((always_inline)) int __bpf_capsule_prepare_continue(struct capsule_result* result, uint64_t continuation, uint32_t* fiber) {
    *result = (struct capsule_result){
        .code = CAPSULE_ERROR_INVALID_CONTINUATION,
        .status = CAPSULE_EXITED,
        .continuation = BPF_CAPSULE_NO_CONTINUATION,
    };
    *fiber = __BPF_CAPSULE_NO_FIBER;
    int consumed = __bpf_capsule_consume_continuation(continuation, fiber);
    if (consumed < 0) {
        if (consumed == __BPF_CAPSULE_CLAIM_MAP_CORRUPT) {
            result->code = CAPSULE_ERROR_POOL_CORRUPT;
        }
        return 0;
    }
    if (!consumed) {
        result->code = CAPSULE_ERROR_STALE_CONTINUATION;
        return 0;
    }
    result->code = 0;
    struct __bpf_capsule_fiber_control* control = __bpf_capsule_fiber_control(*fiber);
    result->continuation = __bpf_capsule_make_continuation(*fiber);
    if (control->status == CAPSULE_EXITED) {
        __bpf_capsule_finish_exited(result, *fiber);
        return 0;
    }
    if (!control->pc) {
        result->code = CAPSULE_ERROR_NOT_PENDING;
        result->status = CAPSULE_EXITED;
        result->continuation = BPF_CAPSULE_NO_CONTINUATION;
        if (__bpf_capsule_fiber_cancel(*fiber)) {
            result->code = CAPSULE_ERROR_POOL_CORRUPT;
        }
        return 0;
    }
    control->status = CAPSULE_OK;
    control->code = 0;
    return 1;
}

static __attribute__((always_inline)) struct capsule_result __bpf_capsule_finish_continue(
    struct capsule_result result, uint32_t fiber, void* output, uint64_t output_size, uint64_t output_alignment) {
    struct __bpf_capsule_fiber_control* control = __bpf_capsule_fiber_control(fiber);
    if (control->status == CAPSULE_EXITED) {
        __bpf_capsule_finish_exited(&result, fiber);
    } else if (control->status == CAPSULE_YIELD) {
        result.status = CAPSULE_YIELD;
        result.continuation = __bpf_capsule_make_continuation(fiber);
    } else if (control->pc) {
        result.status = CAPSULE_PENDING;
        result.continuation = __bpf_capsule_make_continuation(fiber);
    } else {
        if (control->return_size != output_size) {
            result.code = CAPSULE_ERROR_RETURN_MISMATCH;
            result.status = CAPSULE_EXITED;
            if (__bpf_capsule_fiber_cancel(fiber)) {
                result.code = CAPSULE_ERROR_POOL_CORRUPT;
            }
        } else {
            if (output_size) {
                __bpf_capsule_copy_return(fiber, output, output_size, output_alignment);
            }
            if (__bpf_capsule_fiber_release(fiber)) {
                result.code = CAPSULE_ERROR_POOL_CORRUPT;
                result.status = CAPSULE_EXITED;
            } else {
                result.status = CAPSULE_OK;
            }
        }
        if (result.status == CAPSULE_EXITED) {
            control->return_size = 0;
        }
        result.continuation = BPF_CAPSULE_NO_CONTINUATION;
    }
    return result;
}

__BPF_CAPSULE_FN_CLASS("capsule.entry-glue")
__attribute__((always_inline)) struct capsule_result __bpf_capsule_continue(
    void* output, uint64_t output_size, uint64_t output_alignment, uint64_t continuation) {
    struct capsule_result result;
    uint32_t fiber;
    if (!__bpf_capsule_prepare_continue(&result, continuation, &fiber)) {
        return result;
    }
    (void)__bpf_capsule_trampoline(fiber);
    return __bpf_capsule_finish_continue(result, fiber, output, output_size, output_alignment);
}

__BPF_CAPSULE_FN_CLASS("capsule.entry-glue")
__attribute__((always_inline)) struct capsule_result __bpf_capsule_continue_ctx(
    void* context, void* output, uint64_t output_size, uint64_t output_alignment, uint64_t continuation) {
    struct capsule_result result;
    uint32_t fiber;
    if (!__bpf_capsule_prepare_continue(&result, continuation, &fiber)) {
        return result;
    }
    (void)__bpf_capsule_trampoline_ctx((struct xdp_md*)context, fiber);
    return __bpf_capsule_finish_continue(result, fiber, output, output_size, output_alignment);
}

// Cancel a computation and release its fiber; contract in bpf_capsule.h.
__BPF_CAPSULE_FN_CLASS("capsule.entry-glue") __attribute__((always_inline)) struct capsule_result __bpf_capsule_reset(uint64_t continuation) {
    struct capsule_result result = {
        .code = CAPSULE_ERROR_INVALID_CONTINUATION,
        .status = CAPSULE_EXITED,
        .continuation = BPF_CAPSULE_NO_CONTINUATION,
    };
    uint32_t fiber = __BPF_CAPSULE_NO_FIBER;
    int consumed = __bpf_capsule_consume_continuation(continuation, &fiber);
    if (consumed < 0) {
        if (consumed == __BPF_CAPSULE_CLAIM_MAP_CORRUPT) {
            result.code = CAPSULE_ERROR_POOL_CORRUPT;
        }
        return result;
    }
    if (!consumed) {
        result.code = CAPSULE_ERROR_STALE_CONTINUATION;
        return result;
    }
    if (__bpf_capsule_fiber_control(fiber)->status == CAPSULE_EXITED) {
        __bpf_capsule_finish_exited(&result, fiber);
        return result;
    }
    if (__bpf_capsule_fiber_cancel(fiber)) {
        result.code = CAPSULE_ERROR_POOL_CORRUPT;
    } else {
        result.code = 0;
        result.status = CAPSULE_OK;
    }
    return result;
}

// ---------------------------------------------------------------------------
// Wide multiplication, here rather than int128.c because the overflow
// intrinsics appear in ordinary 64-bit code (TLSF's allocator math), so the
// helpers must be present whenever the runtime is. bpf-expand-i128 routes
// llvm.umul/smul.with.overflow here; always_inline folds them back into each
// site after the whole-program link.
// ---------------------------------------------------------------------------

// 64x64 -> 128 as {lo, hi}, in 64-bit arithmetic only.
__attribute__((always_inline)) struct bpf_u128_pair __bpf_mul64_wide(unsigned long long a, unsigned long long b) {
    unsigned long long a0 = a & 0xffffffffull, a1 = a >> 32;
    unsigned long long b0 = b & 0xffffffffull, b1 = b >> 32;
    unsigned long long p00 = a0 * b0, p01 = a0 * b1;
    unsigned long long p10 = a1 * b0, p11 = a1 * b1;
    unsigned long long lo1 = p00 + ((p01 & 0xffffffffull) << 32);
    unsigned long long c1 = lo1 < p00;
    unsigned long long lo2 = lo1 + ((p10 & 0xffffffffull) << 32);
    unsigned long long c2 = lo2 < lo1;
    struct bpf_u128_pair r;
    r.lo = lo2;
    r.hi = p11 + (p01 >> 32) + (p10 >> 32) + c1 + c2;
    return r;
}

// {value, overflowed} for the 64-bit overflow-multiply intrinsics.
__attribute__((always_inline)) struct bpf_u128_pair __bpf_umul64_overflow(unsigned long long a, unsigned long long b) {
    struct bpf_u128_pair p = __bpf_mul64_wide(a, b);
    struct bpf_u128_pair r;
    r.lo = p.lo;
    r.hi = p.hi != 0;
    return r;
}

__attribute__((always_inline)) struct bpf_u128_pair __bpf_smul64_overflow(unsigned long long a, unsigned long long b) {
    struct bpf_u128_pair p = __bpf_mul64_wide(a, b);
    // Signed high half: adjust the unsigned one, then the product fits iff
    // it equals the sign-extension of the low half.
    unsigned long long shi = p.hi - (((long long)a < 0) ? b : 0) - (((long long)b < 0) ? a : 0);
    struct bpf_u128_pair r;
    r.lo = p.lo;
    r.hi = shi != (unsigned long long)((long long)p.lo >> 63);
    return r;
}
