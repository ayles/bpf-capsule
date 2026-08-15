// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception OR GPL-2.0-only
// The complete host-side Capsule API, built on libbpf:
//
//   bpf_capsule_status_string(status)                  status name
//   bpf_capsule_error_string(code)                     framework-error name
//   bpf_capsule_configure(obj, config)                 fibers + heap, pre-load
//   bpf_capsule_finish_initialization(obj)             once after load
//   bpf_capsule_memory(obj, &memory)                    build the memory view
//   bpf_capsule_memory_write(&memory, addr, src, size)  bulk bytes in
//   bpf_capsule_memory_read(&memory, dst, addr, size)   bulk bytes out
//   bpf_capsule_memory_start/size(&memory)              managed image bounds
//   bpf_capsule_memory_reserved_start/size(&memory)     host-reserved heap prefix
//
// The lifecycle is deliberately three separate verbs, each owned by the
// right party: bpf_capsule_configure() before load, then libbpf's own
// bpf_object__load()/bpf_object__load_skeleton(), then
// bpf_capsule_finish_initialization() before the first entry. Loading is
// libbpf's job; nothing here wraps it, prints, or reads environment
// variables.
//
// Nothing here runs entries: invoke them with plain libbpf
// (bpf_prog_test_run_opts, or attach a link) and branch on the
// capsule_result.status your control map publishes. Sectioned control
// globals come from the generated skeleton's typed fields; raw-object
// loaders resolve them with their own BTF walk. Statuses and error codes
// are in bpf_capsule_abi.h; the guest-side API is bpf_capsule.h.
//
// Loaders in other ecosystems (cilium/ebpf, aya) do not link this header:
// SPEC.md "Loader contract" specifies everything a reimplementation needs,
// and the object re-validates any loader's work on its first capsule_call.
// This header is the reference implementation of that contract.
//
// Error convention: every fallible function returns -1 on failure and sets
// errno; zero means success. Capacity/bounds accessors are infallible.
//
// Thread safety: configuration and initialization are not safe to call
// concurrently on the same object, and driving two fibers concurrently
// requires the application to give each its own result mailbox. Distinct
// bpf_object instances are independent; the header keeps no process-global
// state.
#pragma once

#include "bpf_capsule_abi.h"

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#ifdef __cplusplus
extern "C" {
#endif

// Allocation-free names for the shared statuses and framework codes,
// like strerror().

static inline const char* bpf_capsule_status_string(uint32_t status) {
    switch (status) {
        case CAPSULE_OK:
            return "ok";
        case CAPSULE_PENDING:
            return "pending";
        case CAPSULE_YIELD:
            return "yield";
        case CAPSULE_EXITED:
            return "exited";
        default:
            return "unknown status";
    }
}

// Names the framework's negative codes without allocation, like strerror().
// Non-negative codes are the guest's own exit statuses and have no framework
// meaning to name.
static inline const char* bpf_capsule_error_string(int64_t code) {
    switch (code) {
        case CAPSULE_ERROR_POOL_EXHAUSTED:
            return "fiber pool exhausted";
        case CAPSULE_ERROR_INVALID_CONTINUATION:
            return "invalid continuation";
        case CAPSULE_ERROR_STALE_CONTINUATION:
            return "stale continuation";
        case CAPSULE_ERROR_NOT_PENDING:
            return "continuation is not pending";
        case CAPSULE_ERROR_POOL_CORRUPT:
            return "fiber pool corrupt";
        case CAPSULE_ERROR_RETURN_MISMATCH:
            return "return value layout mismatch";
        case CAPSULE_ERROR_STACK_OVERFLOW:
            return "fiber stack overflow";
        case CAPSULE_ERROR_MEMORY_FAULT:
            return "capsule memory fault";
        case CAPSULE_ERROR_INVALID_DISPATCH:
            return "invalid managed dispatch";
        case CAPSULE_ERROR_INTRINSIC_GUARD:
            return "unlowered compiler intrinsic";
        case CAPSULE_ERROR_UNSUPPORTED_FP_INTRINSIC:
            return "unsupported floating-point intrinsic";
        case CAPSULE_ERROR_VLA_BOUNDS:
            return "variable-length array bound exceeded";
        case CAPSULE_ERROR_UNREACHABLE:
            return "unreachable code executed";
        case CAPSULE_ERROR_TRAP:
            return "trap executed";
        case CAPSULE_ERROR_UNSUPPORTED_LIBC:
            return "unsupported libc operation";
        case CAPSULE_ERROR_ALLOCATOR_CORRUPT:
            return "allocator state corrupt";
        case CAPSULE_ERROR_BAD_PLAN:
            return "loader applied an incomplete configuration plan";
        default:
            return code >= 0 ? "guest exit status" : "unknown framework code";
    }
}

// The application-selected capacities. Keeping them in one named value
// makes loader setup self-documenting and leaves compiler-owned layout
// details out of the public API. reserved_bytes carves a host-owned prefix
// out of the heap: managed allocators see only the remaining suffix, the
// host stages bulk input there through the memory view, and both sides may
// pass pointers into it freely.
struct bpf_capsule_config {
    uint32_t fiber_count;
    uint64_t heap_bytes;
    uint64_t reserved_bytes;
};

// The planning arithmetic behind bpf_capsule_configure(): validate the
// requested capacities against the object's .rodata.bpfconfig record, then
// finish the record in place and return the backend map's entry count —
// overflow regions on the fixed-map tier, pages on the arena tier. The
// record carries its own memory tier, so no other input exists, and nothing
// is written until every check has passed. This is the function a
// non-libbpf loader ports (SPEC.md "Loader contract"). Errors: ENOENT the
// record is not this compiler's; EINVAL inconsistent record; E2BIG
// fiber_count above the compiled ceiling; ENOMEM reserved_bytes exceeds the
// heap; EOVERFLOW unrepresentable capacities.
static inline int
__bpf_capsule_plan(struct __bpf_capsule_object_config* config, size_t config_size, struct bpf_capsule_config requested, uint32_t* backend_entries) {
    if (!config || !backend_entries || !requested.fiber_count) {
        errno = EINVAL;
        return -1;
    }
    if (config_size < sizeof(*config)) {
        errno = ENOENT;
        return -1;
    }
    if (requested.fiber_count > config->max_fibers) {
        errno = E2BIG;
        return -1;
    }
    if (!config->stack_bytes_per_fiber || config->heap_base >= BPF_CAPSULE_FUNCTION_TOKEN_BASE || config->uses_arena > 1 ||
        config->abi_magic != BPF_CAPSULE_ABI_MAGIC || config->abi_version != BPF_CAPSULE_ABI_VERSION) {
        errno = EINVAL;
        return -1;
    }
    // The allocator pool follows the reserved prefix; keep its start
    // 16-byte aligned even for an odd reservation.
    if (requested.reserved_bytes > requested.heap_bytes) {
        errno = ENOMEM;
        return -1;
    }
    uint64_t heap_reserved = (requested.reserved_bytes + 15u) & ~15ull;
    if (heap_reserved > requested.heap_bytes) {
        errno = ENOMEM;
        return -1;
    }
    int has_arena = (int)config->uses_arena;
    uint32_t direct_region_maps = has_arena ? 0 : BPF_CAPSULE_DIRECT_MEMORY_REGIONS;

    const uint64_t address_limit = BPF_CAPSULE_FUNCTION_TOKEN_BASE;
    if (requested.heap_bytes > address_limit - config->heap_base) {
        errno = EOVERFLOW;
        return -1;
    }
    uint64_t heap_end = config->heap_base + requested.heap_bytes;

    uint64_t stack_floor = has_arena ? 0 : (uint64_t)direct_region_maps * BPF_CAPSULE_MEMORY_REGION_SIZE;
    uint64_t stack_alignment = has_arena ? BPF_CAPSULE_ARENA_PAGE_SIZE : BPF_CAPSULE_MEMORY_REGION_SIZE;
    uint64_t stack_base = heap_end > stack_floor ? heap_end : stack_floor;
    if (stack_base > address_limit - (stack_alignment - 1u)) {
        errno = EOVERFLOW;
        return -1;
    }
    stack_base = (stack_base + stack_alignment - 1u) & ~(stack_alignment - 1u);
    uint64_t stack_bytes = (uint64_t)config->stack_bytes_per_fiber * requested.fiber_count;
    if (stack_bytes > address_limit - stack_base) {
        errno = EOVERFLOW;
        return -1;
    }
    uint64_t memory_end = stack_base + stack_bytes;

    uint32_t entries;
    if (!has_arena) {
        uint32_t regions = (uint32_t)((memory_end + BPF_CAPSULE_MEMORY_REGION_SIZE - 1u) >> BPF_CAPSULE_MEMORY_REGION_SHIFT);
        entries = regions > direct_region_maps ? regions - direct_region_maps : 0;
        if (!entries) {
            errno = EINVAL;
            return -1;
        }
    } else {
        uint64_t sparse_pages = (memory_end + BPF_CAPSULE_ARENA_PAGE_SIZE - 1u) >> BPF_CAPSULE_ARENA_PAGE_SHIFT;
        uint64_t pages = (uint64_t)config->arena_image_pages + sparse_pages;
        if (!pages || pages > BPF_CAPSULE_MAX_ARENA_PAGES) {
            errno = EOVERFLOW;
            return -1;
        }
        entries = (uint32_t)pages;
    }

    config->fiber_count = requested.fiber_count;
    config->heap_bytes = requested.heap_bytes;
    config->heap_reserved = (uint32_t)heap_reserved;
    config->stack_base = stack_base;
    config->memory_end = memory_end;
    *backend_entries = entries;
    return 0;
}

// Copy an object-owned configuration record only after proving that the map
// contains the complete ABI record. Keeping this boundary separate prevents
// a short or foreign .rodata.bpfconfig map from being dereferenced before the
// loader can return its documented ENOENT result.
static inline int __bpf_capsule_copy_plan(
    const void* config_data, size_t config_size, struct bpf_capsule_config requested, struct __bpf_capsule_object_config* planned, uint32_t* backend_entries
) {
    if (!planned || !backend_entries) {
        errno = EINVAL;
        return -1;
    }
    if (!config_data || config_size < sizeof(*planned)) {
        errno = ENOENT;
        return -1;
    }
    memcpy(planned, config_data, sizeof(*planned));
    return __bpf_capsule_plan(planned, config_size, requested, backend_entries);
}

static inline struct bpf_map* __bpf_capsule_memory_region(struct bpf_object* object, uint32_t index) {
    char name[32];
    snprintf(name, sizeof(name), ".data.heap%u", index);
    struct bpf_map* map = bpf_object__find_map_by_name(object, name);
    if (!map) {
        snprintf(name, sizeof(name), ".bss.heap%u", index);
        map = bpf_object__find_map_by_name(object, name);
    }
    return map;
}

// Select the application-level capacities after open and before load:
// finish the configuration record with the planning arithmetic, then resize
// the fiber maps and the tier's backend map to match it. Calling it again
// before load replaces the previous selection; skipping it entirely is also
// valid, because the compiler stores a complete default layout in the
// object. All validation is the plan's (record-internal) and the object's
// own (first-entry check). Errors: EBUSY the object is
// already loaded; E2BIG fiber_count exceeds the compiled
// BPF_CAPSULE_MAX_FIBERS ceiling; ENOENT the object was not built by this
// compiler; ENOMEM the reservation exceeds the heap; EINVAL/EOVERFLOW
// malformed or unrepresentable capacities. A libbpf map-resize failure is
// returned through the errno corresponding to libbpf's negative error.
static inline int bpf_capsule_configure(struct bpf_object* object, struct bpf_capsule_config requested) {
    if (!object) {
        errno = EINVAL;
        return -1;
    }
    struct bpf_map* config_map = bpf_object__find_map_by_name(object, ".rodata.bpfconfig");
    size_t config_size = 0;
    struct __bpf_capsule_object_config* config = config_map ? (struct __bpf_capsule_object_config*)bpf_map__initial_value(config_map, &config_size) : NULL;
    if (!config) {
        errno = ENOENT;
        return -1;
    }
    if (bpf_map__fd(config_map) >= 0) {
        errno = EBUSY;
        return -1;
    }

    struct __bpf_capsule_object_config planned;
    uint32_t backend_entries = 0;
    if (__bpf_capsule_copy_plan(config, config_size, requested, &planned, &backend_entries)) {
        return -1;
    }

    struct bpf_map* backend = bpf_object__find_map_by_name(object, planned.uses_arena ? "arena" : "bpf_heap_array");
    if (!backend) {
        errno = ENOENT;
        return -1;
    }

    const char* fiber_map_names[] = {
        "bpf_capsule_fiber_leases",
        "bpf_capsule_issued_fibers",
        "bpf_capsule_free_fibers",
        "bpf_capsule_continuation_claims",
    };
    struct bpf_map* fiber_maps[sizeof(fiber_map_names) / sizeof(fiber_map_names[0])] = {0};
    uint32_t old_entries[sizeof(fiber_map_names) / sizeof(fiber_map_names[0])] = {0};
    size_t changed = 0;
    for (size_t i = 0; i < sizeof(fiber_map_names) / sizeof(fiber_map_names[0]); ++i) {
        struct bpf_map* map = bpf_object__find_map_by_name(object, fiber_map_names[i]);
        if (!map) {
            continue;
        }
        fiber_maps[changed] = map;
        old_entries[changed] = bpf_map__max_entries(map);
        int error = bpf_map__set_max_entries(map, requested.fiber_count);
        if (error) {
            int saved_errno = error < 0 ? -error : error;
            while (changed) {
                --changed;
                (void)bpf_map__set_max_entries(fiber_maps[changed], old_entries[changed]);
            }
            errno = saved_errno;
            return -1;
        }
        ++changed;
    }

    int error = bpf_map__set_max_entries(backend, backend_entries);
    if (error) {
        int saved_errno = error < 0 ? -error : error;
        while (changed) {
            --changed;
            (void)bpf_map__set_max_entries(fiber_maps[changed], old_entries[changed]);
        }
        errno = saved_errno;
        return -1;
    }
    *config = planned;
    return 0;
}

// Arena-backed objects have a generated program (bpf_capsule_init) that
// brings up the managed memory: it commits the sparse storage for globals,
// heap, and fiber stacks, publishes the run-time-chosen virtual base, and
// applies pointer-valued global fixups (libbpf applies no relocations
// inside an arena section). Run it once after load, before the first entry.
// On the fixed-map tier every virtual address is a compile-time constant,
// so pointer-valued initializers are already baked into the region images
// in the ELF — there is no such program and this call is a no-op. The
// initializer reports allocation failure through its return value, the
// second error channel of BPF_PROG_TEST_RUN.
static inline int bpf_capsule_finish_initialization(struct bpf_object* object) {
    if (!object) {
        errno = EINVAL;
        return -1;
    }
    struct bpf_program* initializer = bpf_object__find_program_by_name(object, "bpf_capsule_init");
    if (!initializer) {
        return 0;
    }
    int fd = bpf_program__fd(initializer);
    if (fd < 0) {
        errno = -fd;
        return -1;
    }
    struct bpf_test_run_opts options;
    memset(&options, 0, sizeof(options));
    options.sz = sizeof(options);
    int error = bpf_prog_test_run_opts(fd, &options);
    if (error) {
        errno = error < 0 ? -error : error;
        return -1;
    }
    if ((int)options.retval < 0) {
        errno = -(int)options.retval;
        return -1;
    }
    return 0;
}

// One object's managed memory, seen from userspace. Build it once after
// load with bpf_capsule_memory() and pass it to every transfer.
//
// Arena tier: arena_base/arena_size are the load-time userspace mapping of
// the arena map (its identity matters — guest pointers are the low 32 bits
// of that mapping), and arena_control points at the live
// __bpf_capsule_arena_control record in the .data.bpfctrl mapping, so the
// view needs no rebuild when initialization publishes the virtual base.
//
// Fixed-map tier: regions[i] is the mapping of .data.heapN/.bss.heapN map i
// and overflow_fd is the bpf_heap_array map fd, mapped per call for the
// copy.
struct bpf_capsule_memory {
    const struct __bpf_capsule_object_config* config;
    void* arena_base;
    size_t arena_size;
    const volatile struct __bpf_capsule_arena_control* arena_control;
    struct {
        void* base;
        size_t size;
    } regions[BPF_CAPSULE_DIRECT_MEMORY_REGIONS];
    uint32_t region_count;
    int overflow_fd;
    size_t overflow_value_size;
    uint32_t overflow_entries;
};

// Assemble the memory view for one loaded object: the config bytes, the
// arena mapping or the direct-region mappings, and the overflow map fd. The
// view borrows libbpf's mappings and stays valid while the object stays
// loaded.
static inline int bpf_capsule_memory(struct bpf_object* object, struct bpf_capsule_memory* memory) {
    if (!object || !memory) {
        errno = EINVAL;
        return -1;
    }
    memset(memory, 0, sizeof(*memory));
    memory->overflow_fd = -1;

    struct bpf_map* config_map = bpf_object__find_map_by_name(object, ".rodata.bpfconfig");
    size_t config_size = 0;
    const struct __bpf_capsule_object_config* config =
        config_map ? (const struct __bpf_capsule_object_config*)bpf_map__initial_value(config_map, &config_size) : NULL;
    if (!config || config_size < sizeof(*config)) {
        errno = ENOENT;
        return -1;
    }
    if (config->abi_magic != BPF_CAPSULE_ABI_MAGIC || config->abi_version != BPF_CAPSULE_ABI_VERSION || config->memory_end > BPF_CAPSULE_FUNCTION_TOKEN_BASE) {
        errno = EINVAL;
        return -1;
    }
    memory->config = config;

    struct bpf_map* arena = bpf_object__find_map_by_name(object, "arena");
    if (arena) {
        struct bpf_map* control_map = bpf_object__find_map_by_name(object, ".data.bpfctrl");
        size_t control_size = 0;
        const struct __bpf_capsule_arena_control* control =
            control_map ? (const struct __bpf_capsule_arena_control*)bpf_map__initial_value(control_map, &control_size) : NULL;
        if (!control || control_size < sizeof(*control)) {
            errno = EFAULT;
            return -1;
        }
        size_t initialized_size = 0;
        uint8_t* base = (uint8_t*)bpf_map__initial_value(arena, &initialized_size);
        long page_size_result = sysconf(_SC_PAGESIZE);
        size_t page_size = page_size_result > 0 ? (size_t)page_size_result : 0;
        if (!base || !page_size) {
            errno = EFAULT;
            return -1;
        }
        memory->arena_base = base;
        memory->arena_size = (size_t)bpf_map__max_entries(arena) * page_size;
        memory->arena_control = (const volatile struct __bpf_capsule_arena_control*)control;
        return 0;
    }

    while (memory->region_count < BPF_CAPSULE_DIRECT_MEMORY_REGIONS) {
        struct bpf_map* map = __bpf_capsule_memory_region(object, memory->region_count);
        if (!map) {
            break;
        }
        size_t map_size = 0;
        uint8_t* base = (uint8_t*)bpf_map__initial_value(map, &map_size);
        if (!base) {
            errno = EFAULT;
            return -1;
        }
        memory->regions[memory->region_count].base = base;
        memory->regions[memory->region_count].size = map_size;
        ++memory->region_count;
    }
    struct bpf_map* overflow = bpf_object__find_map_by_name(object, "bpf_heap_array");
    if (overflow) {
        memory->overflow_fd = bpf_map__fd(overflow);
        memory->overflow_value_size = bpf_map__value_size(overflow);
        memory->overflow_entries = bpf_map__max_entries(overflow);
    }
    return 0;
}

// Copy bytes through a Capsule virtual address without exposing whether this
// object uses a BPF arena or the fixed-region Linux 5.15 representation.
// This is the userspace memory boundary of an object instance: applications
// may exchange bulk data, while placement and cross-region shadowing stay
// runtime details.
static inline int __bpf_capsule_memory_copy(const struct bpf_capsule_memory* memory, uint64_t address, void* bytes, size_t size, int write_to_capsule) {
    if (!size) {
        return 0;
    }
    if (!memory || !memory->config || !bytes) {
        errno = EINVAL;
        return -1;
    }
    if (address > UINT32_MAX) {
        errno = EFAULT;
        return -1;
    }
    const struct __bpf_capsule_object_config* config = memory->config;

    uint64_t logical_address = address;
    if (memory->arena_base) {
        if (!memory->arena_control || memory->arena_control->ready != 2) {
            errno = EFAULT;
            return -1;
        }
        // Arena pointers are 32-bit values within one complete address
        // window. Subtraction must wrap in that domain: a valid allocation
        // may straddle the low-word boundary of its userspace mapping.
        logical_address = (uint32_t)address - (uint32_t)memory->arena_control->virtual_base;
    }

    uint64_t heap_end = config->heap_base + config->heap_bytes;
    if (heap_end < config->heap_base || config->stack_base < heap_end || config->memory_end < config->stack_base || logical_address >= config->memory_end ||
        size > config->memory_end - logical_address ||
        (logical_address < config->stack_base && size > heap_end - (logical_address < heap_end ? logical_address : heap_end))) {
        errno = EFAULT;
        return -1;
    }

    if (memory->arena_base) {
        uint8_t* base = (uint8_t*)memory->arena_base;
        uint32_t offset = (uint32_t)address - (uint32_t)(uintptr_t)base;
        if (offset >= memory->arena_size || size > memory->arena_size - offset) {
            errno = EFAULT;
            return -1;
        }
        if (write_to_capsule) {
            memcpy(base + offset, bytes, size);
        } else {
            memcpy(bytes, base + offset, size);
        }
        return 0;
    }

    // Fixed-map objects expose their prefix as direct region mappings.
    // Capacity beyond that prefix is one BPF_F_MMAPABLE ARRAY map. Map it
    // once for the complete copy: a syscall lookup would otherwise copy an
    // entire 2 MiB value for every small host access.
    uint8_t* overflow_base = NULL;
    size_t overflow_size = 0;
    size_t overflow_stride = 0;
    if (memory->overflow_fd >= 0 && memory->overflow_entries) {
        long page_size_result = sysconf(_SC_PAGESIZE);
        size_t page_size = page_size_result > 0 ? (size_t)page_size_result : 0;
        overflow_stride = (memory->overflow_value_size + 7u) & ~(size_t)7u;
        if (!page_size || overflow_stride < memory->overflow_value_size || overflow_stride > SIZE_MAX / memory->overflow_entries) {
            errno = EOVERFLOW;
            return -1;
        }
        size_t values_size = overflow_stride * memory->overflow_entries;
        if (values_size > SIZE_MAX - (page_size - 1u)) {
            errno = EOVERFLOW;
            return -1;
        }
        overflow_size = (values_size + page_size - 1u) & ~(page_size - 1u);
        overflow_base = (uint8_t*)mmap(NULL, overflow_size, PROT_READ | PROT_WRITE, MAP_SHARED, memory->overflow_fd, 0);
        if (overflow_base == MAP_FAILED) {
            return -1;
        }
    }

    uint8_t* cursor = (uint8_t*)bytes;
    uint64_t offset = address;
    size_t remaining = size;
    int error = 0;
    while (remaining) {
        uint32_t region = (uint32_t)(offset >> BPF_CAPSULE_MEMORY_REGION_SHIFT);
        size_t in_region = (size_t)offset & (BPF_CAPSULE_MEMORY_REGION_SIZE - 1);
        size_t part = BPF_CAPSULE_MEMORY_REGION_SIZE - in_region;
        if (part > remaining) {
            part = remaining;
        }
        uint8_t* base = NULL;
        size_t map_size = 0;
        if (region < memory->region_count) {
            base = (uint8_t*)memory->regions[region].base;
            map_size = memory->regions[region].size;
        } else if (overflow_base && region - memory->region_count < memory->overflow_entries) {
            base = overflow_base + (size_t)(region - memory->region_count) * overflow_stride;
            map_size = memory->overflow_value_size;
        }
        if (!base || in_region + part > map_size) {
            errno = EFAULT;
            error = -1;
            break;
        }
        if (write_to_capsule) {
            memcpy(base + in_region, cursor, part);
        } else {
            memcpy(cursor, base + in_region, part);
        }

        // Old-kernel regions carry an eight-byte suffix mirroring the next
        // region so unaligned scalar loads can cross a verifier map boundary.
        // Refresh it whenever this write touches that next region's prefix.
        if (write_to_capsule && region && in_region < 8) {
            uint32_t previous_region = region - 1;
            uint8_t* previous_base = NULL;
            size_t previous_size = 0;
            if (previous_region < memory->region_count) {
                previous_base = (uint8_t*)memory->regions[previous_region].base;
                previous_size = memory->regions[previous_region].size;
            } else if (overflow_base && previous_region - memory->region_count < memory->overflow_entries) {
                previous_base = overflow_base + (size_t)(previous_region - memory->region_count) * overflow_stride;
                previous_size = memory->overflow_value_size;
            }
            if (!previous_base || previous_size < BPF_CAPSULE_MEMORY_REGION_SIZE + 8 || map_size < 8) {
                errno = EFAULT;
                error = -1;
                break;
            }
            memcpy(previous_base + BPF_CAPSULE_MEMORY_REGION_SIZE, base, 8);
        }
        cursor += part;
        offset += part;
        remaining -= part;
    }
    if (overflow_base) {
        munmap(overflow_base, overflow_size);
    }
    return error;
}

// Bulk transfer between host memory and Capsule addresses (heap
// reservations, published guest globals) over the view built once by
// bpf_capsule_memory(). Addresses must fall inside the object's managed
// image — the fiber-stack bank included, so writing a live fiber's stack is
// possible and is the caller's responsibility to avoid. Errors: EFAULT
// address range outside the image or an uninitialized arena (a failing
// multi-region copy may have written earlier regions); EINVAL/EOVERFLOW
// malformed view or arguments; or the errno reported by mmap() while opening
// the fixed tier's overflow storage.
static inline int bpf_capsule_memory_write(const struct bpf_capsule_memory* memory, uint64_t address, const void* source, size_t size) {
    return __bpf_capsule_memory_copy(memory, address, (void*)source, size, 1);
}

static inline int bpf_capsule_memory_read(const struct bpf_capsule_memory* memory, void* destination, uint64_t address, size_t size) {
    return __bpf_capsule_memory_copy(memory, address, destination, size, 0);
}

// Observability over the view: the managed image's bounds in the external
// virtual address domain, and the host-reserved heap prefix selected at
// configure time. Capsule addresses live in the low 32 bits; on the arena
// tier the start is meaningful once bpf_capsule_finish_initialization() has
// run (the base reads as zero before then) and arithmetic wraps in that
// 32-bit domain like every capsule pointer.
static inline uint64_t bpf_capsule_memory_size(const struct bpf_capsule_memory* memory) {
    return memory && memory->config ? memory->config->memory_end : 0;
}

static inline uint64_t bpf_capsule_memory_start(const struct bpf_capsule_memory* memory) {
    if (!memory || !memory->config) {
        return 0;
    }
    return memory->arena_control ? (uint32_t)memory->arena_control->virtual_base : 0;
}

// The reserved prefix opens the heap: staging input there keeps it out of
// the allocator's reach for the object's whole lifetime, and both sides may
// pass pointers into it freely.
static inline uint64_t bpf_capsule_memory_reserved_size(const struct bpf_capsule_memory* memory) {
    return memory && memory->config ? memory->config->heap_reserved : 0;
}

static inline uint64_t bpf_capsule_memory_reserved_start(const struct bpf_capsule_memory* memory) {
    if (!memory || !memory->config) {
        return 0;
    }
    uint64_t base = memory->config->heap_base;
    return memory->arena_control ? (uint32_t)(memory->arena_control->virtual_base + base) : base;
}

#ifdef __cplusplus
}
#endif
