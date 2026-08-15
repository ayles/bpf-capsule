// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
// The Capsule runtime: maps, globals, the trampoline drivers, the fiber
// pool, and the machinery behind the capsule_call family declared in
// bpf_capsule.h. The build pipeline compiles this file into every object
// automatically — application code never includes or compiles it, and the
// whole-program llvm-link resolves the extern glue the public macros expand
// to.
//
// Reserved names. The runtime owns the maps `arena`, `bpf_heap_array`, and
// `bpf_capsule_*`, the program `bpf_capsule_init`, the ELF sections
// `.rodata.bpfconfig`, `.bss.bpfctrl`, `.data.bpfctrl`, and
// `.data.heapN`/`.bss.heapN`, and every `__bpf_capsule_*` and `bpf_heap_*`
// symbol. Do not declare, resize, or write these from application code.
//
//   BPF_CAPSULE_TARGET_KERNEL
//                       the oldest kernel the object must load on. Everything
//                       below follows from it, and it has to match the
//                       -bpf-target given to opt.
//   __arena             qualifier for objects the memory model relocates.
//   bpf_heap_*          the accessors the memory pass routes loads and stores
//                       through when there is no bpf_arena.
//
// A program supplies its own sectioned native entry points and crosses into a
// compiler-managed closure explicitly with capsule_call(). On the arena tier
// the memory pass inserts a once-only initialization prologue in every entry.
// The map tier's image is complete in the ELF and needs no run-time hook.
// Application source calls neither initialization mechanism.

#include "bpf_capsule.h"
#include "bpf_capsule_abi.h"

#include <linux/bpf.h>
#include <linux/errno.h>
#include <bpf/bpf_helpers.h>

#ifndef BPF_CAPSULE_TARGET_KERNEL
#define BPF_CAPSULE_TARGET_KERNEL 5015
#endif

// The memory tier follows the selected kernel floor. The continuation driver
// is shared by both tiers, so control-flow semantics do not change with it.
#ifndef BPF_HAS_ARENA
#define BPF_HAS_ARENA (BPF_CAPSULE_TARGET_KERNEL >= 6009)
#endif

// Bytes of software stack per fiber. Must be a power of two, at most 2 MiB,
// and must equal the -bpf-fiber-stack-size the passes were given — the
// compiler rejects a mismatch at build time. The CMake pipeline keeps the
// two in sync from the BPF_CAPSULE_FIBER_STACK_BYTES cache variable.
#ifndef BPF_CAPSULE_FIBER_STACK_BYTES
#define BPF_CAPSULE_FIBER_STACK_BYTES (256u * 1024u)
#endif

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

#if BPF_HAS_ARENA

struct {
    __uint(type, BPF_MAP_TYPE_ARENA);
    __uint(map_flags, BPF_F_MMAPABLE);
    // Compiler placeholder: the arena pass replaces this with the exact page
    // capacity required by initialized data plus sparse program storage.
    __uint(max_entries, 1);
} arena SEC(".maps");

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
// Low 32 bits of the sparse allocation returned by bpf_arena_alloc_pages,
// together with its 0 -> 1 -> 2 initialization state. The compiler adds
// per-object offsets to virtual_base and casts the result back to address
// space 1 only when memory is accessed.
struct __bpf_capsule_arena_control bpf_capsule_arena_control SEC(".data.bpfctrl") = {0};

#else

#ifndef __arena
#define __arena
#endif

// The compiler lays out ordinary globals, generates the fast directly
// relocatable 2 MiB maps selected by policy, and places any zero-filled
// overflow in this multi-entry ARRAY map. It also synthesizes the width-
// specific dynamic accessors and boundary-shadow maintenance. The ARRAY map
// removes the former 64 MiB heap ceiling; direct maps remain the default hot
// path because they avoid a lookup at each dynamically addressed access.
struct bpf_heap_array_value {
    uint8_t bytes[BPF_CAPSULE_MEMORY_REGION_SIZE + 8u];
};
struct bpf_capsule_stack_value {
    uint8_t bytes[BPF_CAPSULE_FIBER_STACK_BYTES];
};
// max_entries is a compiler placeholder. The fixed-map layout pass replaces
// its BTF array bound with the exact number of zero-filled overflow regions;
// the kernel then allocates precisely the heap requested by the program.
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(map_flags, BPF_F_MMAPABLE);
    __uint(max_entries, 1);
    __type(key, uint32_t);
    __type(value, struct bpf_heap_array_value);
} bpf_heap_array SEC(".maps");

#endif /* BPF_HAS_ARENA */

// ---------------------------------------------------------------- driver
//
// Managed code runs on a software call stack. The trampoline dispatches its
// top frame until it drains, using nested bounded global functions whose
// verification cost adds while their iteration counts multiply.
extern int __bpf_capsule_trampoline(uint32_t fiber);

struct __bpf_capsule_fiber_control bpf_capsule_fibers[BPF_CAPSULE_MAX_FIBERS] SEC(".bss.bpfctrl");

const volatile struct __bpf_capsule_object_config bpf_capsule_config SEC(".rodata.bpfconfig") = {
    .heap_base = 0,
    .heap_bytes = BPF_CAPSULE_DEFAULT_HEAP_BYTES,
    .stack_base = 0,
    .memory_end = 0,
    .fiber_count = 1,
    .stack_bytes_per_fiber = BPF_CAPSULE_FIBER_STACK_BYTES,
    .max_fibers = BPF_CAPSULE_MAX_FIBERS,
    .arena_image_pages = 0,
    .uses_arena = BPF_HAS_ARENA ? 1u : 0u,
    .heap_reserved = 0,
    .abi_magic = BPF_CAPSULE_ABI_MAGIC,
    .abi_version = BPF_CAPSULE_ABI_VERSION,
};

static __attribute__((always_inline)) uint32_t __bpf_capsule_fiber_count(void) {
    uint32_t count = bpf_capsule_config.fiber_count;
    return count >= 1 && count <= BPF_CAPSULE_MAX_FIBERS ? count : 0;
}

static __attribute__((always_inline)) struct __bpf_capsule_fiber_control* __bpf_capsule_fiber_control(uint32_t fiber);

// One encoded word carries both the terminal tag and the signed code; see
// the layout comment in bpf_capsule_abi.h.
static __attribute__((always_inline)) uint64_t __bpf_capsule_exit_encode(int32_t code) {
    return ((uint64_t)(int64_t)code << 32) | CAPSULE_EXITED;
}

// Released fibers are recycled in O(1) on the modern tier. A LIFO stack keeps
// sequential calls on the same warm fiber whenever possible. Stack maps are
// born empty, and libbpf cannot currently describe their initial contents, so
// a second, permanent set records which IDs have ever been issued. The first
// BPF_CAPSULE_MAX_FIBERS acquisitions claim a new ID with BPF_NOEXIST; after that
// the issued set is read only and every successful acquire is one stack pop.
//
// Linux 5.15 forbids stack maps in sleepable programs (including the syscall
// programs used by BPF_PROG_TEST_RUN), so its portable representation is the
// exact active-lease set. It scans only at acquisition, never needs a JIT
// atomic, and keeps arbitrary loaders initializer-free. Keep both lease hashes
// preallocated: Linux 5.15 rejects BPF_F_NO_PREALLOC maps referenced by a
// sleepable program. bpf_capsule_configure() resizes these maps to the active
// count before load; even an unconfigured 512-entry map is only a small
// control-plane allocation. Stack backing also follows the runtime-active
// fiber count, subject to the fixed tier's 2 MiB map-value granularity.
#if BPF_HAS_ARENA
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, BPF_CAPSULE_MAX_FIBERS);
    __type(key, uint32_t);
    __type(value, uint32_t);
} bpf_capsule_issued_fibers SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_STACK);
    __uint(max_entries, BPF_CAPSULE_MAX_FIBERS);
    __type(value, uint32_t);
} bpf_capsule_free_fibers SEC(".maps");
#else
// Linux 5.15 cannot use a stack map from the sleepable syscall programs used
// by BPF_PROG_TEST_RUN, so the active lease itself is the complete set.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, BPF_CAPSULE_MAX_FIBERS);
    __type(key, uint32_t);
    __type(value, uint64_t);
} bpf_capsule_fiber_leases SEC(".maps");
#endif

// A continuation is consumed by claiming its complete generation-tagged
// token with BPF_NOEXIST. The claim exists only for the duration of one
// continue/reset entry; the helper operation is the cross-CPU linearization
// point. This avoids BPF_CMPXCHG, which the Linux 5.15 arm64 verifier accepts
// but its JIT cannot emit.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, BPF_CAPSULE_MAX_FIBERS);
    __type(key, uint64_t);
    __type(value, uint32_t);
} bpf_capsule_continuation_claims SEC(".maps");

// Generated by bpf-stackify: one dispatch of the top frame, non-zero once the
// stack is empty.
#if BPF_HAS_ARENA
extern int __bpf_capsule_trampoline_step(uint32_t fiber, struct __bpf_capsule_fiber_control* fiber_control);
#else
// Compiler intrinsic: bpf-memory replaces this with the one ARRAY lookup that
// obtains the bpf_heap_array region containing the current fiber stack. The
// resulting pointer is valid only during this outer drive and is never stored
// in Capsule memory. This is not a separate stack map or address space.
extern struct bpf_heap_array_value* __bpf_capsule_stack_region(uint32_t fiber);
extern int __bpf_capsule_trampoline_step(uint32_t fiber, struct __bpf_capsule_fiber_control* fiber_control, struct bpf_capsule_stack_value* stack_base);
#endif

// Borrowed verifier pointers cannot be stored in maps or arena memory. XDP
// calls use a parallel typed driver that keeps the exact PTR_TO_CTX provenance
// in BPF registers/native spills through every global subprogram call. The
// compiler supplies the step definition and selects this driver only for a
// capsule_call whose root has a pointer argument.
#if BPF_HAS_ARENA
extern int __bpf_capsule_trampoline_ctx_step(struct xdp_md* ctx, uint32_t fiber, struct __bpf_capsule_fiber_control* fiber_control);
#else
extern int __bpf_capsule_trampoline_ctx_step(
    struct xdp_md* ctx, uint32_t fiber, struct __bpf_capsule_fiber_control* fiber_control, struct bpf_capsule_stack_value* stack_base
);
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
// Iterations therefore multiply while verification only adds. This loop runs
// The nested driver dispatches for roughly four instructions of simulation
// per inner iteration, and the
// entry program repeats the whole thing, giving span * repeats dispatches for
// span + repeats worth of verification.
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
#if BPF_HAS_ARENA
#define __BPF_CAPSULE_STACK_PARAMETER
#define __BPF_CAPSULE_STACK_ARGUMENT
#else
#define __BPF_CAPSULE_STACK_PARAMETER , struct bpf_capsule_stack_value* stack_base
#define __BPF_CAPSULE_STACK_ARGUMENT , stack_base
#endif
#define __BPF_CAPSULE_CONTROL_PARAMETER , struct __bpf_capsule_fiber_control* fiber_control
#define __BPF_CAPSULE_CONTROL_ARGUMENT , fiber_control

__attribute__((noinline)) int __bpf_capsule_trampoline_l1(uint32_t fiber __BPF_CAPSULE_CONTROL_PARAMETER __BPF_CAPSULE_STACK_PARAMETER) {
    for (int i = 0; i < BPF_CAPSULE_DRIVE_LEVEL; i++) {
        int status = __bpf_capsule_trampoline_step(fiber __BPF_CAPSULE_CONTROL_ARGUMENT __BPF_CAPSULE_STACK_ARGUMENT);
        if (status) {
            return status; // finished or aborted
        }
    }
    return 0;
}

int __bpf_capsule_trampoline(uint32_t fiber) {
    struct __bpf_capsule_fiber_control* fiber_control = __bpf_capsule_fiber_control(fiber);
#if !BPF_HAS_ARENA
    struct bpf_heap_array_value* stack_region = __bpf_capsule_stack_region(fiber);
    if (!stack_region) {
        __bpf_capsule_fiber_control(fiber)->exit_word = __bpf_capsule_exit_encode(CAPSULE_ERROR_MEMORY_FAULT);
        return 1;
    }
    uint32_t stack_region_offset = (fiber * BPF_CAPSULE_FIBER_STACK_BYTES) & (BPF_CAPSULE_MEMORY_REGION_SIZE - 1u);
    struct bpf_capsule_stack_value* stack_base = (struct bpf_capsule_stack_value*)(stack_region->bytes + stack_region_offset);
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
__attribute__((used, noinline)) int
__bpf_capsule_trampoline_ctx_l1(struct xdp_md* ctx, uint32_t fiber __BPF_CAPSULE_CONTROL_PARAMETER __BPF_CAPSULE_STACK_PARAMETER) {
    for (int i = 0; i < BPF_CAPSULE_DRIVE_LEVEL; i++) {
        int status = __bpf_capsule_trampoline_ctx_step(ctx, fiber __BPF_CAPSULE_CONTROL_ARGUMENT __BPF_CAPSULE_STACK_ARGUMENT);
        if (status) {
            return status;
        }
    }
    return 0;
}

__attribute__((used)) int __bpf_capsule_trampoline_ctx(struct xdp_md* ctx, uint32_t fiber) {
    struct __bpf_capsule_fiber_control* fiber_control = __bpf_capsule_fiber_control(fiber);
#if !BPF_HAS_ARENA
    struct bpf_heap_array_value* stack_region = __bpf_capsule_stack_region(fiber);
    if (!stack_region) {
        __bpf_capsule_fiber_control(fiber)->exit_word = __bpf_capsule_exit_encode(CAPSULE_ERROR_MEMORY_FAULT);
        return 1;
    }
    uint32_t stack_region_offset = (fiber * BPF_CAPSULE_FIBER_STACK_BYTES) & (BPF_CAPSULE_MEMORY_REGION_SIZE - 1u);
    struct bpf_capsule_stack_value* stack_base = (struct bpf_capsule_stack_value*)(stack_region->bytes + stack_region_offset);
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

static __attribute__((always_inline)) uint64_t __bpf_capsule_exit_word(uint32_t fiber) {
    if (fiber >= BPF_CAPSULE_MAX_FIBERS) {
        return 0;
    }
    return __bpf_capsule_fiber_control(fiber)->exit_word;
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
    return __bpf_capsule_continuation_value(fiber, bpf_capsule_fibers[fiber].generation);
}

__attribute__((used, noinline)) uint32_t __bpf_capsule_fiber_acquire_chunk(uint32_t start, uint32_t first) {
    uint32_t count = __bpf_capsule_fiber_count();
    if (start >= count || first >= count) {
        return __BPF_CAPSULE_NO_FIBER;
    }

#if BPF_HAS_ARENA
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
#if BPF_HAS_ARENA
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

static __attribute__((always_inline)) void __bpf_capsule_prepare_fiber(uint32_t fiber) {
    struct __bpf_capsule_fiber_control* control = &bpf_capsule_fibers[fiber];
#if BPF_HAS_ARENA
    control->generation = __bpf_capsule_next_generation(control->generation);
#endif
    control->exit_word = 0;
    control->stack_cursor = 0;
    control->return_size = 0;
}

__attribute__((used, noinline)) uint32_t __bpf_capsule_fiber_acquire(void) {
    uint32_t count = __bpf_capsule_fiber_count();
    uint32_t fiber = __BPF_CAPSULE_NO_FIBER;
    if (!count) {
        return __BPF_CAPSULE_NO_FIBER;
    }
#if BPF_HAS_ARENA
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
#if BPF_HAS_ARENA
    struct __bpf_capsule_fiber_control* control = &bpf_capsule_fibers[fiber];
    if ((control->stack_cursor || (uint32_t)control->exit_word == CAPSULE_EXITED) && control->generation == generation) {
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
            __bpf_capsule_fiber_control(fiber)->exit_word = __bpf_capsule_exit_encode(CAPSULE_ERROR_POOL_CORRUPT);
        }
        return consumed ? __BPF_CAPSULE_CLAIM_CONSUMED : __BPF_CAPSULE_CLAIM_MAP_CORRUPT;
    }
    return consumed;
}

__attribute__((used, noinline)) int __bpf_capsule_fiber_release(uint32_t fiber) {
    if (fiber >= __bpf_capsule_fiber_count()) {
        return -1;
    }
#if BPF_HAS_ARENA
    if (bpf_map_push_elem(&bpf_capsule_free_fibers, &fiber, 0) != 0) {
        // A full stack means a duplicate release or damaged pool. Keep the
        // slot visibly unavailable instead of risking concurrent reuse.
        bpf_capsule_fibers[fiber].exit_word = __bpf_capsule_exit_encode(CAPSULE_ERROR_POOL_CORRUPT);
        return -1;
    }
#else
    if (bpf_map_delete_elem(&bpf_capsule_fiber_leases, &fiber) != 0) {
        bpf_capsule_fibers[fiber].exit_word = __bpf_capsule_exit_encode(CAPSULE_ERROR_POOL_CORRUPT);
        return -1;
    }
#endif
    return 0;
}

static __attribute__((always_inline)) int __bpf_capsule_fiber_cancel(uint32_t fiber) {
    struct __bpf_capsule_fiber_control* control = __bpf_capsule_fiber_control(fiber);
    control->exit_word = 0;
    control->stack_cursor = 0;
    control->return_size = 0;
    return __bpf_capsule_fiber_release(fiber);
}

__attribute__((always_inline)) void __bpf_capsule_finish_exited(struct capsule_result* result, uint32_t fiber) {
    uint64_t word = __bpf_capsule_exit_word(fiber);
    result->code = (int64_t)word >> 32;
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
        bpf_capsule_config.uses_arena != (BPF_HAS_ARENA ? 1u : 0u) || !bpf_capsule_config.stack_bytes_per_fiber || heap_end < bpf_capsule_config.heap_base ||
        bpf_capsule_config.stack_base < heap_end || bpf_capsule_config.memory_end != bpf_capsule_config.stack_base + stack_bytes ||
        bpf_capsule_config.heap_reserved > bpf_capsule_config.heap_bytes || bpf_capsule_config.abi_magic != BPF_CAPSULE_ABI_MAGIC ||
        bpf_capsule_config.abi_version != BPF_CAPSULE_ABI_VERSION || bpf_capsule_config.memory_end > BPF_CAPSULE_FUNCTION_TOKEN_BASE) {
        return 1;
    }
#if !BPF_HAS_ARENA
    // The overflow array must reach the last planned region; a stale
    // max_entries would otherwise fault only when a deep access lands there.
    uint32_t last_region = (uint32_t)((bpf_capsule_config.memory_end - 1u) >> BPF_CAPSULE_MEMORY_REGION_SHIFT);
    if (last_region >= BPF_CAPSULE_DIRECT_MEMORY_REGIONS) {
        uint32_t key = last_region - BPF_CAPSULE_DIRECT_MEMORY_REGIONS;
        if (!bpf_map_lookup_elem(&bpf_heap_array, &key)) {
            return 1;
        }
    }
#endif
    return 0;
}

__attribute__((always_inline)) struct capsule_result
__bpf_capsule_continue(void* output, uint64_t output_size, uint64_t output_alignment, uint64_t continuation) {
    struct capsule_result result = {
        .code = CAPSULE_ERROR_INVALID_CONTINUATION,
        .status = CAPSULE_EXITED,
        .reserved = 0,
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
    result.code = 0;
    struct __bpf_capsule_fiber_control* control = __bpf_capsule_fiber_control(fiber);
    result.continuation = __bpf_capsule_make_continuation(fiber);
    if ((uint32_t)control->exit_word == CAPSULE_EXITED) {
        __bpf_capsule_finish_exited(&result, fiber);
        return result;
    }
    if (!control->stack_cursor) {
        result.code = CAPSULE_ERROR_NOT_PENDING;
        result.status = CAPSULE_EXITED;
        result.continuation = BPF_CAPSULE_NO_CONTINUATION;
        if (__bpf_capsule_fiber_cancel(fiber)) {
            result.code = CAPSULE_ERROR_POOL_CORRUPT;
        }
        return result;
    }
    control->exit_word = 0;
    (void)__bpf_capsule_trampoline(fiber);
    if ((uint32_t)control->exit_word == CAPSULE_EXITED) {
        __bpf_capsule_finish_exited(&result, fiber);
    } else if ((uint32_t)control->exit_word == CAPSULE_YIELD) {
        result.status = CAPSULE_YIELD;
        result.continuation = __bpf_capsule_make_continuation(fiber);
    } else if (control->stack_cursor) {
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

// Cancel a computation and release its fiber; contract in bpf_capsule.h.
__attribute__((always_inline)) struct capsule_result __bpf_capsule_reset(uint64_t continuation) {
    struct capsule_result result = {
        .code = CAPSULE_ERROR_INVALID_CONTINUATION,
        .status = CAPSULE_EXITED,
        .reserved = 0,
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
    if ((uint32_t)__bpf_capsule_fiber_control(fiber)->exit_word == CAPSULE_EXITED) {
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
