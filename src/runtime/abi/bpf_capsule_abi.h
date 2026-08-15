// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#pragma once

#include <stdint.h>

// The host <-> guest ABI: everything both sides of a Capsule object read and
// write. The guest API is bpf_capsule.h; the host API is bpf_capsule_host.h;
// both include this header.

#define BPF_CAPSULE_ABI_MAGIC 0x42504341u /* "BPCA" */
#define BPF_CAPSULE_ABI_VERSION 1u

// This discriminator makes mismatched objects and loaders fail explicitly;
// it is not a pre-1.0 stability promise. An incompatible layout change bumps
// the version, and callers must rebuild object and host from one installation.

// Capsule addresses occupy the low portion of the 32-bit logical domain. The
// final 2 MiB are function tokens: keeping the namespaces disjoint makes an
// invalid data-as-function conversion fail dispatch, and an invalid
// function-as-data conversion fail the memory bounds check.
#define BPF_CAPSULE_FUNCTION_TOKEN_BASE 0xffe00000u
#define BPF_CAPSULE_MANAGED_FUNCTION_TOKEN_LIMIT 0x00100000u
#define BPF_CAPSULE_NO_CONTINUATION UINT64_MAX

// Result of entering or continuing a Capsule computation. CAPSULE_PENDING
// means the compiled in-kernel drive span ended before the computation did;
// it is not an error, and the caller may resume it with capsule_continue().
// The continuation field is meaningful for CAPSULE_PENDING and CAPSULE_YIELD;
// the code field is meaningful for CAPSULE_EXITED.
enum capsule_status {
    CAPSULE_OK = 0,
    CAPSULE_PENDING = 1,
    CAPSULE_YIELD = 2,
    CAPSULE_EXITED = 3,
};

// One signed termination code space, shaped like a shell's $?:
//
//   0 .. 255   the guest's own exit status — capsule_exit(code) masks with
//              0xff exactly as POSIX observes exit(); by convention the Lua
//              adapter exits 1 on a script error, the Rust panic handler
//              exits 101, and freestanding abort() exits 134 (128+SIGABRT).
//   negative   the framework stopped the computation. Only the compiler and
//              runtime produce these; guest code cannot. Named below and
//              printed by the host's bpf_capsule_error_string().
#define CAPSULE_ERROR_POOL_EXHAUSTED (-1)
#define CAPSULE_ERROR_INVALID_CONTINUATION (-2)
#define CAPSULE_ERROR_STALE_CONTINUATION (-3)
#define CAPSULE_ERROR_NOT_PENDING (-4)
#define CAPSULE_ERROR_POOL_CORRUPT (-5)
#define CAPSULE_ERROR_RETURN_MISMATCH (-6)
#define CAPSULE_ERROR_STACK_OVERFLOW (-7)
#define CAPSULE_ERROR_MEMORY_FAULT (-8)
#define CAPSULE_ERROR_INVALID_DISPATCH (-9)
#define CAPSULE_ERROR_INTRINSIC_GUARD (-10)
#define CAPSULE_ERROR_UNSUPPORTED_FP_INTRINSIC (-11)
#define CAPSULE_ERROR_VLA_BOUNDS (-12)
#define CAPSULE_ERROR_UNREACHABLE (-13)
#define CAPSULE_ERROR_TRAP (-14)
#define CAPSULE_ERROR_UNSUPPORTED_LIBC (-15)
#define CAPSULE_ERROR_ALLOCATOR_CORRUPT (-16)
#define CAPSULE_ERROR_BAD_PLAN (-17)

struct capsule_result {
    int64_t code;
    uint32_t status;
    // Reserved ABI padding: writers set it to zero and readers ignore it.
    // Naming the field also prevents aggregate copies from reading an
    // uninitialized native-stack hole, which the BPF verifier rejects.
    uint32_t reserved;
    uint64_t continuation;
};

#ifdef __cplusplus
#define __BPF_CAPSULE_ABI_ASSERT(condition, message) static_assert(condition, message)
#else
#define __BPF_CAPSULE_ABI_ASSERT(condition, message) _Static_assert(condition, message)
#endif

__BPF_CAPSULE_ABI_ASSERT(__builtin_offsetof(struct capsule_result, code) == 0, "capsule_result.code ABI");
__BPF_CAPSULE_ABI_ASSERT(__builtin_offsetof(struct capsule_result, status) == 8, "capsule_result.status ABI");
__BPF_CAPSULE_ABI_ASSERT(__builtin_offsetof(struct capsule_result, reserved) == 12, "capsule_result.reserved ABI");
__BPF_CAPSULE_ABI_ASSERT(__builtin_offsetof(struct capsule_result, continuation) == 16, "capsule_result.continuation ABI");
__BPF_CAPSULE_ABI_ASSERT(sizeof(struct capsule_result) == 24, "capsule_result size ABI");

// ------------------------------------------------------------- object layout

#define BPF_CAPSULE_MEMORY_REGION_SHIFT 21u
#define BPF_CAPSULE_MEMORY_REGION_SIZE (1u << BPF_CAPSULE_MEMORY_REGION_SHIFT)
#define BPF_CAPSULE_DIRECT_MEMORY_REGIONS 32u
#define BPF_CAPSULE_ARENA_PAGE_SHIFT 12u
#define BPF_CAPSULE_ARENA_PAGE_SIZE (1u << BPF_CAPSULE_ARENA_PAGE_SHIFT)
#define BPF_CAPSULE_MAX_ARENA_PAGES (1u << (32u - BPF_CAPSULE_ARENA_PAGE_SHIFT))

// Per-fiber control words in .bss.bpfctrl. No hand-written host code reads
// these, but generated skeletons type the section with this record, so its
// layout is ABI. A host that polls sectioned application mailboxes concurrently
// with BPF execution needs an application-level synchronization protocol;
// volatile access alone supplies no inter-CPU ordering. exit_word encodes a
// terminated computation's code and the
// terminal tag in one value: ((uint64_t)(int64_t)code << 32) |
// CAPSULE_EXITED, decoded with an arithmetic shift right by 32. The tag in
// the low half is what keeps a guest exit(0) distinguishable from "still
// running"; the sign-preserving shift is what lets the framework's negative
// codes share the word.
struct __bpf_capsule_fiber_control {
    uint64_t exit_word;
    uint64_t stack_cursor;
    uint64_t return_size;
    uint64_t generation;
};

enum __bpf_capsule_fiber_control_field {
    BPF_CAPSULE_FIBER_CONTROL_EXIT_WORD,
    BPF_CAPSULE_FIBER_CONTROL_STACK_CURSOR,
    BPF_CAPSULE_FIBER_CONTROL_RETURN_SIZE,
    BPF_CAPSULE_FIBER_CONTROL_GENERATION,
    BPF_CAPSULE_FIBER_CONTROL_FIELD_COUNT,
};

__BPF_CAPSULE_ABI_ASSERT(__builtin_offsetof(struct __bpf_capsule_fiber_control, exit_word) == 0, "fiber control exit_word ABI");
__BPF_CAPSULE_ABI_ASSERT(__builtin_offsetof(struct __bpf_capsule_fiber_control, stack_cursor) == 8, "fiber control stack_cursor ABI");
__BPF_CAPSULE_ABI_ASSERT(__builtin_offsetof(struct __bpf_capsule_fiber_control, return_size) == 16, "fiber control return_size ABI");
__BPF_CAPSULE_ABI_ASSERT(__builtin_offsetof(struct __bpf_capsule_fiber_control, generation) == 24, "fiber control generation ABI");
__BPF_CAPSULE_ABI_ASSERT(sizeof(struct __bpf_capsule_fiber_control) == 32, "fiber control size ABI");

// The arena initializer publishes its sparse allocation through one stable
// control record. Keeping this as one object makes the userspace mmap layout
// explicit instead of relying on relative placement of separate globals.
struct __bpf_capsule_arena_control {
    uint32_t ready;
    uint32_t reserved;
    uint64_t virtual_base;
};

// The compiler fills the layout fields. The host may change only
// fiber_count, heap_bytes, and heap_reserved before load;
// bpf_capsule_configure() derives the selected stack base and memory end and
// the backend map sizes it applies. uses_arena records the object's memory
// tier so planning needs no facts beyond this record. heap_reserved is the
// host-owned prefix of the heap: managed allocators see only the remaining
// suffix, while reserved bytes remain ordinary unified-memory storage that
// may be passed to managed code by pointer.
struct __bpf_capsule_object_config {
    uint64_t heap_base;
    uint64_t heap_bytes;
    uint64_t stack_base;
    uint64_t memory_end;
    uint32_t fiber_count;
    uint32_t stack_bytes_per_fiber;
    uint32_t max_fibers;
    uint32_t arena_image_pages;
    uint32_t uses_arena;
    uint32_t heap_reserved;
    uint32_t abi_magic;
    uint32_t abi_version;
};

// LLVM struct types do not preserve C field names. Compiler passes therefore
// use these shared indices rather than independently duplicating a positional
// ABI that could silently drift from the host/guest record above.
enum __bpf_capsule_object_config_field {
    BPF_CAPSULE_OBJECT_CONFIG_HEAP_BASE,
    BPF_CAPSULE_OBJECT_CONFIG_HEAP_BYTES,
    BPF_CAPSULE_OBJECT_CONFIG_STACK_BASE,
    BPF_CAPSULE_OBJECT_CONFIG_MEMORY_END,
    BPF_CAPSULE_OBJECT_CONFIG_FIBER_COUNT,
    BPF_CAPSULE_OBJECT_CONFIG_STACK_BYTES_PER_FIBER,
    BPF_CAPSULE_OBJECT_CONFIG_MAX_FIBERS,
    BPF_CAPSULE_OBJECT_CONFIG_ARENA_IMAGE_PAGES,
    BPF_CAPSULE_OBJECT_CONFIG_USES_ARENA,
    BPF_CAPSULE_OBJECT_CONFIG_HEAP_RESERVED,
    BPF_CAPSULE_OBJECT_CONFIG_ABI_MAGIC,
    BPF_CAPSULE_OBJECT_CONFIG_ABI_VERSION,
    BPF_CAPSULE_OBJECT_CONFIG_FIELD_COUNT,
};

__BPF_CAPSULE_ABI_ASSERT(__builtin_offsetof(struct __bpf_capsule_object_config, heap_base) == 0, "object config heap_base ABI");
__BPF_CAPSULE_ABI_ASSERT(__builtin_offsetof(struct __bpf_capsule_object_config, heap_bytes) == 8, "object config heap_bytes ABI");
__BPF_CAPSULE_ABI_ASSERT(__builtin_offsetof(struct __bpf_capsule_object_config, stack_base) == 16, "object config stack_base ABI");
__BPF_CAPSULE_ABI_ASSERT(__builtin_offsetof(struct __bpf_capsule_object_config, memory_end) == 24, "object config memory_end ABI");
__BPF_CAPSULE_ABI_ASSERT(__builtin_offsetof(struct __bpf_capsule_object_config, fiber_count) == 32, "object config fiber_count ABI");
__BPF_CAPSULE_ABI_ASSERT(__builtin_offsetof(struct __bpf_capsule_object_config, stack_bytes_per_fiber) == 36, "object config stack_bytes_per_fiber ABI");
__BPF_CAPSULE_ABI_ASSERT(__builtin_offsetof(struct __bpf_capsule_object_config, max_fibers) == 40, "object config max_fibers ABI");
__BPF_CAPSULE_ABI_ASSERT(__builtin_offsetof(struct __bpf_capsule_object_config, arena_image_pages) == 44, "object config arena_image_pages ABI");
__BPF_CAPSULE_ABI_ASSERT(__builtin_offsetof(struct __bpf_capsule_object_config, uses_arena) == 48, "object config uses_arena ABI");
__BPF_CAPSULE_ABI_ASSERT(__builtin_offsetof(struct __bpf_capsule_object_config, heap_reserved) == 52, "object config heap_reserved ABI");
__BPF_CAPSULE_ABI_ASSERT(__builtin_offsetof(struct __bpf_capsule_object_config, abi_magic) == 56, "object config abi_magic ABI");
__BPF_CAPSULE_ABI_ASSERT(__builtin_offsetof(struct __bpf_capsule_object_config, abi_version) == 60, "object config abi_version ABI");
__BPF_CAPSULE_ABI_ASSERT(sizeof(struct __bpf_capsule_object_config) == 64, "object config size ABI");

#undef __BPF_CAPSULE_ABI_ASSERT
