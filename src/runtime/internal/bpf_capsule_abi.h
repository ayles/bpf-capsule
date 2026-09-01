// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#pragma once

#include "bpf_capsule_types.h"

#include <stdint.h>

// Private object ABI shared by the compiler, runtime, and host loader.
// Application code includes bpf_capsule.h or bpf_capsule_host.h instead.

#define BPF_CAPSULE_ABI_MAGIC 0x42504341u /* "BPCA" */
#define BPF_CAPSULE_ABI_VERSION 5u

// This discriminator makes mismatched objects and loaders fail explicitly;
// it is not a pre-1.0 stability promise. An incompatible layout change bumps
// the version, and callers must rebuild object and host from one installation.

// Every capsule pointer is window + displacement, where the window is the
// 4GiB-aligned span bpf_capsule_configure() reserves (on the arena tier it
// is the arena's kernel-pinned user_vm_start). Data lives in the window's
// first 4GiB. Code lives just above it: a managed function's address is
// window + TOKEN_DISPLACEMENT + entry-pc, and non-managed function
// identities follow in the next 1MiB — so code and data can never collide
// as 64-bit values, and because the window is 4GiB-aligned an indirect
// call recovers the entry pc by truncating the token to its low word (free
// in BPF: 32-bit ALU zero-extends). The token span is part of the
// PROT_NONE reservation, so dereferencing a function pointer faults on the
// host and falls outside every map on the guest.
#define BPF_CAPSULE_FUNCTION_TOKEN_DISPLACEMENT (1ull << 32)
#define BPF_CAPSULE_MANAGED_FUNCTION_TOKEN_LIMIT 0x00100000u
#define BPF_CAPSULE_FUNCTION_TOKEN_SPAN (2ull * BPF_CAPSULE_MANAGED_FUNCTION_TOKEN_LIMIT)
#define BPF_CAPSULE_MEMORY_WINDOW_SIZE (BPF_CAPSULE_FUNCTION_TOKEN_DISPLACEMENT + BPF_CAPSULE_FUNCTION_TOKEN_SPAN)

#ifdef __cplusplus
#define __BPF_CAPSULE_ABI_ASSERT(condition, message) static_assert(condition, message)
#else
#define __BPF_CAPSULE_ABI_ASSERT(condition, message) _Static_assert(condition, message)
#endif

// ------------------------------------------------------------- object layout

#define BPF_CAPSULE_MEMORY_REGION_SHIFT 21u
#define BPF_CAPSULE_MEMORY_REGION_SIZE (1u << BPF_CAPSULE_MEMORY_REGION_SHIFT)
// Fixed-tier overflow ARRAY values carry the region plus this pad so the
// per-entry stride is page-aligned on 4K/16K/64K hosts and each entry can
// be mapped individually into the contiguous host view. The first eight pad
// bytes are the cross-region shadow suffix; the rest is dead space (~3%).
#define BPF_CAPSULE_MEMORY_REGION_PAD 65536u
#define BPF_CAPSULE_DIRECT_MEMORY_REGIONS 32u
#define BPF_CAPSULE_ARENA_PAGE_SHIFT 12u
#define BPF_CAPSULE_ARENA_PAGE_SIZE (1u << BPF_CAPSULE_ARENA_PAGE_SHIFT)
#define BPF_CAPSULE_MAX_ARENA_PAGES (1u << (32u - BPF_CAPSULE_ARENA_PAGE_SHIFT))
// The arena sparse allocation carries one extra fiber slice of pages so the
// guest initializer can publish a virtual_base aligned to the slice size
// (the kernel's own placement is only page-aligned, and the compiler's
// stack-slice mask is exact only from an aligned base). Every page-budget
// computation — the compiler's baked max_entries, the host resize, and the
// guest allocation — must include this same term.
#define BPF_CAPSULE_ARENA_SLICE_SLACK_PAGES(stack_bytes_per_fiber) \
    ((uint64_t)(stack_bytes_per_fiber) > BPF_CAPSULE_ARENA_PAGE_SIZE ? (uint64_t)(stack_bytes_per_fiber) / BPF_CAPSULE_ARENA_PAGE_SIZE - 1u : 0u)

// Per-fiber control words in .bss.bpfctrl. No hand-written host code reads
// these, but generated skeletons type the section with this record, so its
// layout is ABI. A host that polls sectioned application mailboxes concurrently
// with BPF execution needs an application-level synchronization protocol;
// volatile access alone supplies no inter-CPU ordering.
//
// {status, code} is the terminal event: status stays CAPSULE_OK (zero, the
// zero-initialized state) while the computation runs and becomes
// CAPSULE_EXITED or CAPSULE_YIELD when a region publishes an outcome; code
// carries the signed termination code for CAPSULE_EXITED. The pair is
// adjacent and 8-byte aligned so the compiler's exit lowering publishes both
// with one 64-bit store ((int64_t)code << 32 | status, little-endian); every
// legal reader is ordered after that store by program order or by the
// continuation claim, so the fields read independently.
//
// The virtualized machine registers. pc is a resume-point index, never an
// address, and doubles as the lifecycle word: 0 = idle (an all-zero record
// is a free fiber, which is what makes a fresh zero-filled map a valid
// pool), BPF_CAPSULE_PC_DONE = computation complete and unconsumed,
// anything else = a live entry/resume PC. sp is the allocation frontier and
// fp the running frame's x86-shaped anchor; both are full based pointers into
// capsule memory, the same representation the guest and host dereference.
// fp points at the saved caller fp, the 32-bit return pc occupies fp+8, and
// the caller-owned result and actual arguments follow at positive offsets.
// Locals and dynamic allocations grow toward lower addresses. There is no
// result register. return_size is the erased return type's byte-count witness,
// checked when a type-blind continuation reap copies the root result.
struct __bpf_capsule_fiber_control {
    enum capsule_status status;
    int32_t code;
    uint64_t generation;
    uint64_t sp;
    uint64_t fp;
    uint32_t pc;
    uint32_t return_size;
};

#define BPF_CAPSULE_PC_DONE UINT32_MAX

__BPF_CAPSULE_ABI_ASSERT(__builtin_offsetof(struct __bpf_capsule_fiber_control, status) == 0, "fiber control status ABI");
__BPF_CAPSULE_ABI_ASSERT(__builtin_offsetof(struct __bpf_capsule_fiber_control, code) == 4, "fiber control code ABI");
__BPF_CAPSULE_ABI_ASSERT(__builtin_offsetof(struct __bpf_capsule_fiber_control, generation) == 8, "fiber control generation ABI");
__BPF_CAPSULE_ABI_ASSERT(__builtin_offsetof(struct __bpf_capsule_fiber_control, sp) == 16, "fiber control sp ABI");
__BPF_CAPSULE_ABI_ASSERT(__builtin_offsetof(struct __bpf_capsule_fiber_control, fp) == 24, "fiber control fp ABI");
__BPF_CAPSULE_ABI_ASSERT(__builtin_offsetof(struct __bpf_capsule_fiber_control, pc) == 32, "fiber control pc ABI");
__BPF_CAPSULE_ABI_ASSERT(__builtin_offsetof(struct __bpf_capsule_fiber_control, return_size) == 36, "fiber control return_size ABI");
__BPF_CAPSULE_ABI_ASSERT(sizeof(struct __bpf_capsule_fiber_control) == 40, "fiber control size ABI");

// The arena initializer publishes its sparse allocation through one stable
// control record. Keeping this as one object makes the userspace mmap layout
// explicit instead of relying on relative placement of separate globals.
struct __bpf_capsule_arena_control {
    uint32_t ready;
    uint32_t reserved;
    uintptr_t virtual_base;
};

enum bpf_capsule_memory_backend {
    BPF_CAPSULE_MEMORY_FIXED = 0,
    BPF_CAPSULE_MEMORY_ARENA = 1,
};

// The compiler fills the layout fields. The host may change only fiber_count,
// heap_bytes, and heap_reserved before load; bpf_capsule_configure() derives
// the selected stack base, memory end, and arena size. Layout displacements
// and capacities are 32-bit because data occupies the first 4 GiB of the
// object window; guest pointers themselves are full-width window +
// displacement values, and function tokens occupy the disjoint span above
// data. Data page zero contains no program object (heap_base is always at
// least BPF_CAPSULE_ARENA_PAGE_SIZE), and the prepared host view protects the
// same page so null-plus-offset dereferences fault. heap_reserved is the
// host-owned prefix of the heap: managed allocators see only the remaining
// suffix, while reserved bytes remain ordinary unified-memory storage that
// may be passed to managed code by pointer.
struct __bpf_capsule_object_config {
    uint32_t heap_base;
    uint32_t heap_bytes;
    uint32_t stack_base;
    uint32_t memory_end;
    uint32_t fiber_count;
    uint32_t stack_bytes_per_fiber;
    uint32_t max_fibers;
    uint32_t arena_image_pages;
    uint32_t memory_backend;
    uint32_t heap_reserved;
    uint32_t abi_magic;
    uint32_t abi_version;
    // Host-chosen base of the contiguous process mapping of capsule memory.
    // The compiler emits zero, and mandatory pre-load bpf_capsule_configure()
    // replaces it with a nonzero base before the record is frozen. Guest
    // pointers are memory_view_base + displacement on both tiers; the
    // verifier folds the frozen read, so the guest pays no runtime lookup.
    uintptr_t memory_view_base;
};

__BPF_CAPSULE_ABI_ASSERT(__builtin_offsetof(struct __bpf_capsule_object_config, heap_base) == 0, "object config heap_base ABI");
__BPF_CAPSULE_ABI_ASSERT(__builtin_offsetof(struct __bpf_capsule_object_config, heap_bytes) == 4, "object config heap_bytes ABI");
__BPF_CAPSULE_ABI_ASSERT(__builtin_offsetof(struct __bpf_capsule_object_config, stack_base) == 8, "object config stack_base ABI");
__BPF_CAPSULE_ABI_ASSERT(__builtin_offsetof(struct __bpf_capsule_object_config, memory_end) == 12, "object config memory_end ABI");
__BPF_CAPSULE_ABI_ASSERT(__builtin_offsetof(struct __bpf_capsule_object_config, fiber_count) == 16, "object config fiber_count ABI");
__BPF_CAPSULE_ABI_ASSERT(__builtin_offsetof(struct __bpf_capsule_object_config, stack_bytes_per_fiber) == 20, "object config stack_bytes_per_fiber ABI");
__BPF_CAPSULE_ABI_ASSERT(__builtin_offsetof(struct __bpf_capsule_object_config, max_fibers) == 24, "object config max_fibers ABI");
__BPF_CAPSULE_ABI_ASSERT(__builtin_offsetof(struct __bpf_capsule_object_config, arena_image_pages) == 28, "object config arena_image_pages ABI");
__BPF_CAPSULE_ABI_ASSERT(__builtin_offsetof(struct __bpf_capsule_object_config, memory_backend) == 32, "object config memory_backend ABI");
__BPF_CAPSULE_ABI_ASSERT(__builtin_offsetof(struct __bpf_capsule_object_config, heap_reserved) == 36, "object config heap_reserved ABI");
__BPF_CAPSULE_ABI_ASSERT(__builtin_offsetof(struct __bpf_capsule_object_config, abi_magic) == 40, "object config abi_magic ABI");
__BPF_CAPSULE_ABI_ASSERT(__builtin_offsetof(struct __bpf_capsule_object_config, abi_version) == 44, "object config abi_version ABI");
__BPF_CAPSULE_ABI_ASSERT(__builtin_offsetof(struct __bpf_capsule_object_config, memory_view_base) == 48, "object config memory_view_base ABI");
__BPF_CAPSULE_ABI_ASSERT(sizeof(struct __bpf_capsule_object_config) == 56, "object config size ABI");

#undef __BPF_CAPSULE_ABI_ASSERT
