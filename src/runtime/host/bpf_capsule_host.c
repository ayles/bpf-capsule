// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception OR GPL-2.0-only
// Host-side Capsule setup, memory access, and lifetime management.
#include "bpf_capsule_host.h"
#include "bpf_capsule_abi.h"
#include "bpf_capsule_names.h"

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

// Allocation-free names for the shared statuses and framework codes,
// like strerror().

const char* bpf_capsule_status_string(uint32_t status) {
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
const char* bpf_capsule_error_string(int64_t code) {
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
        case CAPSULE_ERROR_UNREACHABLE:
            return "unreachable code executed";
        case CAPSULE_ERROR_TRAP:
            return "trap executed";
        case CAPSULE_ERROR_ALLOCATOR_CORRUPT:
            return "allocator state corrupt";
        case CAPSULE_ERROR_BAD_PLAN:
            return "loader applied an incomplete configuration plan";
        default:
            return code >= 0 ? "guest exit status" : "unknown framework code";
    }
}

struct bpf_capsule_state {
    void* window;
    const struct __bpf_capsule_object_config* config;
    void* arena_base;
    size_t arena_size;
    const volatile struct __bpf_capsule_arena_control* arena_control;
    struct {
        void* base;
        size_t size;
        int fd;
    } regions[BPF_CAPSULE_DIRECT_MEMORY_REGIONS];
    uint32_t region_count;
    void* view;
    size_t view_size;
    int overflow_fd;
    size_t overflow_value_size;
    uint32_t overflow_entries;
};

static struct bpf_capsule_state* __bpf_capsule_state(const struct bpf_capsule* capsule) {
    return capsule ? (struct bpf_capsule_state*)capsule->private_data : NULL;
}

static inline int __bpf_capsule_layout_header_valid(const struct __bpf_capsule_object_config* config) {
    return config->stack_bytes_per_fiber && !(config->stack_bytes_per_fiber & (config->stack_bytes_per_fiber - 1u)) &&
        config->stack_bytes_per_fiber <= BPF_CAPSULE_MEMORY_REGION_SIZE && config->max_fibers && config->max_fibers <= BPF_CAPSULE_MAX_FIBERS_LIMIT &&
        config->heap_base >= BPF_CAPSULE_ARENA_PAGE_SIZE && config->heap_base <= UINT32_MAX && config->memory_backend <= BPF_CAPSULE_MEMORY_ARENA &&
        config->abi_magic == BPF_CAPSULE_ABI_MAGIC && config->abi_version == BPF_CAPSULE_ABI_VERSION;
}

// The planning arithmetic behind bpf_capsule_configure(): validate the
// requested capacities against the object's .rodata.bpfconfig record, then
// finish the record in place and return the backend map's entry count —
// overflow regions on the fixed-map tier, pages on the arena tier. The
// record carries its own memory tier, so no other input exists, and nothing
// is written until every check has passed. This is the function a
// non-libbpf loader ports. Errors: ENOENT the
// record is not this compiler's; EINVAL inconsistent record; E2BIG
// fiber_count above the compiled ceiling; ENOMEM reserved_bytes exceeds the
// heap; EOVERFLOW unrepresentable capacities.
int __bpf_capsule_plan(struct __bpf_capsule_object_config* config, size_t config_size, struct bpf_capsule_config requested, uint32_t* backend_entries) {
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
    if (!__bpf_capsule_layout_header_valid(config)) {
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
    int has_arena = config->memory_backend == BPF_CAPSULE_MEMORY_ARENA;
    uint32_t direct_region_maps = has_arena ? 0 : BPF_CAPSULE_DIRECT_MEMORY_REGIONS;

    const uint64_t address_limit = 1ull << 32;
    if (requested.heap_bytes > address_limit - config->heap_base) {
        errno = EOVERFLOW;
        return -1;
    }
    uint64_t heap_end = config->heap_base + requested.heap_bytes;

    uint64_t stack_floor = has_arena ? 0 : (uint64_t)direct_region_maps * BPF_CAPSULE_MEMORY_REGION_SIZE;
    // Mirrors the compiler's ConfigureObjectLayout: the stack bank must
    // start on a stack_bytes_per_fiber boundary, because sp/fp are full
    // pointer values and the compiled slice mask is exact only then (the
    // fixed tier's region alignment already covers it — slices are at most
    // one region).
    uint64_t stack_alignment = has_arena
        ? (config->stack_bytes_per_fiber > BPF_CAPSULE_ARENA_PAGE_SIZE ? config->stack_bytes_per_fiber : BPF_CAPSULE_ARENA_PAGE_SIZE)
        : BPF_CAPSULE_MEMORY_REGION_SIZE;
    uint64_t stack_base = heap_end > stack_floor ? heap_end : stack_floor;
    if (stack_base > address_limit - (stack_alignment - 1u)) {
        errno = EOVERFLOW;
        return -1;
    }
    stack_base = (stack_base + stack_alignment - 1u) & ~(stack_alignment - 1u);
    uint64_t stack_bytes = (uint64_t)config->stack_bytes_per_fiber * requested.fiber_count;
    if (stack_bytes >= address_limit - stack_base) {
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
        uint64_t pages = (uint64_t)config->arena_image_pages + sparse_pages + BPF_CAPSULE_ARENA_SLICE_SLACK_PAGES(config->stack_bytes_per_fiber);
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
int __bpf_capsule_copy_plan(
    const void* config_data, size_t config_size, struct bpf_capsule_config requested, struct __bpf_capsule_object_config* planned, uint32_t* backend_entries) {
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
    snprintf(name, sizeof(name), BPF_CAPSULE_SECTION_DATA_HEAP_PREFIX "%u", index);
    struct bpf_map* map = bpf_object__find_map_by_name(object, name);
    if (!map) {
        snprintf(name, sizeof(name), BPF_CAPSULE_SECTION_BSS_HEAP_PREFIX "%u", index);
        map = bpf_object__find_map_by_name(object, name);
    }
    return map;
}

// Reserve one PROT_NONE window of address space: 4GiB-aligned, covering the
// full 32-bit offset domain plus the function-token range above it. The
// alignment makes base + offset == base | offset, so the guest recovers an
// offset by truncating to the low word (free in BPF: 32-bit ALU
// zero-extends); the PROT_NONE span makes any stray dereference of a
// capsule-shaped pointer fault instead of aliasing unrelated mappings.
// Address space is free with MAP_NORESERVE; only the leading alignment
// slack is returned.
static inline uintptr_t __bpf_capsule_reserve_window(void) {
    const uintptr_t view_alignment = 1ull << 32;
    const uintptr_t token_tail = BPF_CAPSULE_FUNCTION_TOKEN_SPAN;
    size_t reserve = (size_t)(2 * view_alignment + token_tail);
    uint8_t* raw = (uint8_t*)mmap(NULL, reserve, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);
    if (raw == MAP_FAILED) {
        return 0;
    }
    uint8_t* aligned = (uint8_t*)(((uintptr_t)raw + view_alignment - 1u) & ~(view_alignment - 1u));
    if (aligned != raw) {
        munmap(raw, (size_t)(aligned - raw));
    }
    size_t tail = reserve - (size_t)(aligned - raw) - (size_t)(view_alignment + token_tail);
    if (tail) {
        munmap(aligned + view_alignment + token_tail, tail);
    }
    return (uintptr_t)aligned;
}

static inline int __bpf_capsule_restore_reservation(void* address, size_t size) {
    void* restored = mmap(address, size, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED | MAP_NORESERVE, -1, 0);
    return restored == MAP_FAILED ? -1 : 0;
}

// MANDATORY, once per object after open and before load — this is the
// host-side half of the object's memory identity, not an optional tuning
// knob. It selects the application-level capacities (finish the
// configuration record with the planning arithmetic, then resize the fiber
// maps and the tier's backend map to match it), reserves the object's
// 4GiB-aligned memory window, and bakes the window base into the
// to-be-frozen config, where the object's first-entry check demands a
// nonzero value. On the fixed tier the window is where
// bpf_capsule_initialize() later assembles the read view, so guest
// pointers are host pointers; on the arena tier the window becomes the
// arena's kernel-pinned user_vm_start (libbpf maps the arena into it with
// MAP_FIXED at load). Calling it again before load replaces the previous
// selection (the prior window reservation is released). Errors: EBUSY the
// object is already loaded; E2BIG fiber_count exceeds the compiled
// BPF_CAPSULE_MAX_FIBERS ceiling; ENOENT the object was not built by this
// compiler; ENOMEM the reservation exceeds the heap or no window is
// available; EINVAL/EOVERFLOW malformed or unrepresentable capacities. A
// libbpf map-resize failure is returned through the errno corresponding to
// libbpf's negative error.
int bpf_capsule_configure(struct bpf_capsule* capsule, struct bpf_object* object, struct bpf_capsule_config requested) {
    if (!capsule || !object) {
        errno = EINVAL;
        return -1;
    }
    struct bpf_capsule_state* state = __bpf_capsule_state(capsule);
    if ((capsule->object && capsule->object != object) || (!capsule->object && state)) {
        errno = EBUSY;
        return -1;
    }
    struct bpf_map* config_map = bpf_object__find_map_by_name(object, BPF_CAPSULE_SECTION_CONFIG);
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
    if (config->memory_view_base != (uintptr_t)(state ? state->window : NULL)) {
        // A reservation can only be replaced by the handle that owns it.
        errno = EBUSY;
        return -1;
    }

    struct __bpf_capsule_object_config planned;
    uint32_t backend_entries = 0;
    if (__bpf_capsule_copy_plan(config, config_size, requested, &planned, &backend_entries)) {
        return -1;
    }

    struct bpf_map* backend =
        bpf_object__find_map_by_name(object, planned.memory_backend == BPF_CAPSULE_MEMORY_ARENA ? BPF_CAPSULE_MAP_ARENA : BPF_CAPSULE_MAP_HEAP_ARRAY);
    if (!backend) {
        errno = ENOENT;
        return -1;
    }

    const char* fiber_map_names[3] = {0};
    size_t fiber_map_count = 0;
    if (planned.memory_backend == BPF_CAPSULE_MEMORY_ARENA) {
        fiber_map_names[fiber_map_count++] = BPF_CAPSULE_MAP_ISSUED_FIBERS;
        fiber_map_names[fiber_map_count++] = BPF_CAPSULE_MAP_FREE_FIBERS;
    } else {
        fiber_map_names[fiber_map_count++] = BPF_CAPSULE_MAP_FIBER_LEASES;
    }
    fiber_map_names[fiber_map_count++] = BPF_CAPSULE_MAP_CONTINUATION_CLAIMS;
    struct bpf_map* fiber_maps[3] = {0};
    uint32_t old_entries[3] = {0};
    for (size_t i = 0; i < fiber_map_count; ++i) {
        fiber_maps[i] = bpf_object__find_map_by_name(object, fiber_map_names[i]);
        if (!fiber_maps[i]) {
            errno = ENOENT;
            return -1;
        }
        old_entries[i] = bpf_map__max_entries(fiber_maps[i]);
    }

    // Reserve first so a failed replacement leaves the old configuration and
    // every libbpf map property untouched.
    uintptr_t window = __bpf_capsule_reserve_window();
    if (!window) {
        errno = ENOMEM;
        return -1;
    }
    int new_state = state == NULL;
    if (new_state) {
        state = (struct bpf_capsule_state*)calloc(1, sizeof(*state));
        if (!state) {
            (void)munmap((void*)window, (size_t)BPF_CAPSULE_MEMORY_WINDOW_SIZE);
            return -1;
        }
        state->overflow_fd = -1;
    }

    size_t changed = 0;
    for (size_t i = 0; i < fiber_map_count; ++i) {
        int error = bpf_map__set_max_entries(fiber_maps[i], requested.fiber_count);
        if (error) {
            int saved_errno = error < 0 ? -error : error;
            while (changed) {
                --changed;
                (void)bpf_map__set_max_entries(fiber_maps[changed], old_entries[changed]);
            }
            (void)munmap((void*)(uintptr_t)window, (size_t)BPF_CAPSULE_MEMORY_WINDOW_SIZE);
            if (new_state) {
                free(state);
            }
            errno = saved_errno;
            return -1;
        }
        changed = i + 1;
    }

    uint32_t old_backend_entries = bpf_map__max_entries(backend);
    uint64_t old_map_extra = bpf_map__map_extra(backend);
    int error = bpf_map__set_max_entries(backend, backend_entries);
    if (error) {
        int saved_errno = error < 0 ? -error : error;
        while (changed) {
            --changed;
            (void)bpf_map__set_max_entries(fiber_maps[changed], old_entries[changed]);
        }
        (void)munmap((void*)(uintptr_t)window, (size_t)BPF_CAPSULE_MEMORY_WINDOW_SIZE);
        if (new_state) {
            free(state);
        }
        errno = saved_errno;
        return -1;
    }

    if (planned.memory_backend == BPF_CAPSULE_MEMORY_ARENA) {
        // The arena claims the window at load: libbpf passes map_extra as
        // the kernel-pinned user_vm_start and maps the arena there with
        // MAP_FIXED, replacing exactly the pages it owns; the rest of the
        // window stays PROT_NONE so wild capsule-shaped pointers fault.
        error = (int)bpf_map__set_map_extra(backend, window);
        if (error) {
            int saved_errno = error < 0 ? -error : error;
            (void)bpf_map__set_map_extra(backend, old_map_extra);
            (void)bpf_map__set_max_entries(backend, old_backend_entries);
            while (changed) {
                --changed;
                (void)bpf_map__set_max_entries(fiber_maps[changed], old_entries[changed]);
            }
            (void)munmap((void*)(uintptr_t)window, (size_t)BPF_CAPSULE_MEMORY_WINDOW_SIZE);
            if (new_state) {
                free(state);
            }
            errno = saved_errno;
            return -1;
        }
    }
    void* old_window = state->window;
    planned.memory_view_base = window;
    *config = planned;
    capsule->object = object;
    capsule->private_data = state;
    state->window = (void*)window;
    if (old_window) {
        (void)munmap(old_window, (size_t)BPF_CAPSULE_MEMORY_WINDOW_SIZE);
    }
    return 0;
}

// End the host lifetime and release its complete address-space window. Call
// this after the last entry and memory-view release. Success clears the handle,
// so cleanup paths may call it after partial setup and may call it repeatedly.
int bpf_capsule_release(struct bpf_capsule* capsule) {
    if (!capsule) {
        errno = EINVAL;
        return -1;
    }
    struct bpf_capsule_state* state = __bpf_capsule_state(capsule);
    if (!state) {
        capsule->object = NULL;
        return 0;
    }
    if (state->window && munmap(state->window, (size_t)BPF_CAPSULE_MEMORY_WINDOW_SIZE)) {
        return -1;
    }
    free(state);
    memset(capsule, 0, sizeof(*capsule));
    return 0;
}

// MANDATORY, once after load and before the first entry — entries fail
// closed until initialization has completed; there is no lazy fallback.
// Arena-backed objects have a generated program (bpf_capsule_init) that
// brings up the managed memory: it commits the sparse storage for globals,
// heap, and fiber stacks, publishes the run-time-chosen virtual base, and
// applies pointer-valued global fixups (libbpf applies no relocations
// inside an arena section). On the fixed-map tier it applies the compiler's
// `.rodata.bpffix` pointer-fixup table to the loaded image and publishes the
// readiness word. The initializer reports
// allocation failure through its return value, the second error channel of
// BPF_PROG_TEST_RUN.
// (Defined after the memory helpers below, which the fixed tier's fixup
// application uses.)
int bpf_capsule_initialize(struct bpf_capsule* capsule);

// Bind the loaded object's maps to its existing lifetime. Arena mappings are
// borrowed from libbpf; the fixed tier maps its regions over the reserved
// window so guest-published pointers are directly readable by the host.
static int __bpf_capsule_prepare_memory(struct bpf_capsule* capsule) {
    struct bpf_capsule_state* state = __bpf_capsule_state(capsule);
    if (!capsule || !capsule->object || !state || !state->window) {
        errno = EINVAL;
        return -1;
    }
    if (state->config) {
        return 0;
    }
    struct bpf_object* object = capsule->object;
    state->arena_base = NULL;
    state->arena_size = 0;
    state->arena_control = NULL;
    memset(state->regions, 0, sizeof(state->regions));
    state->region_count = 0;
    state->view = NULL;
    state->view_size = 0;
    state->overflow_fd = -1;
    state->overflow_value_size = 0;
    state->overflow_entries = 0;

    struct bpf_map* config_map = bpf_object__find_map_by_name(object, BPF_CAPSULE_SECTION_CONFIG);
    size_t config_size = 0;
    const struct __bpf_capsule_object_config* config =
        config_map ? (const struct __bpf_capsule_object_config*)bpf_map__initial_value(config_map, &config_size) : NULL;
    if (!config || config_size < sizeof(*config)) {
        errno = ENOENT;
        return -1;
    }
    if (config->memory_view_base != (uintptr_t)state->window) {
        errno = EINVAL;
        return -1;
    }
    uint64_t heap_end = (uint64_t)config->heap_base + config->heap_bytes;
    uint64_t stack_bytes = (uint64_t)config->stack_bytes_per_fiber * config->fiber_count;
    if (!__bpf_capsule_layout_header_valid(config) || !config->fiber_count || config->fiber_count > config->max_fibers ||
        config->heap_reserved > config->heap_bytes || (config->heap_reserved & 15u) || heap_end > config->stack_base || config->stack_base > UINT32_MAX ||
        stack_bytes > (1ull << 32) - config->stack_base || config->memory_end != config->stack_base + stack_bytes) {
        errno = EINVAL;
        return -1;
    }
    struct bpf_map* arena = bpf_object__find_map_by_name(object, BPF_CAPSULE_MAP_ARENA);
    if (config->memory_backend == BPF_CAPSULE_MEMORY_ARENA) {
        if (!arena) {
            errno = ENOENT;
            return -1;
        }
        struct bpf_map* control_map = bpf_object__find_map_by_name(object, BPF_CAPSULE_SECTION_ARENA_CONTROL);
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
        if (!base || !page_size || bpf_map__max_entries(arena) > SIZE_MAX / page_size) {
            errno = EFAULT;
            return -1;
        }
        state->arena_base = base;
        state->arena_size = (size_t)bpf_map__max_entries(arena) * page_size;
        state->arena_control = (const volatile struct __bpf_capsule_arena_control*)control;
        state->config = config;
        return 0;
    }
    if (config->memory_backend != BPF_CAPSULE_MEMORY_FIXED || arena) {
        errno = EINVAL;
        return -1;
    }

    while (state->region_count < BPF_CAPSULE_DIRECT_MEMORY_REGIONS) {
        struct bpf_map* map = __bpf_capsule_memory_region(object, state->region_count);
        if (!map) {
            break;
        }
        size_t map_size = 0;
        uint8_t* base = (uint8_t*)bpf_map__initial_value(map, &map_size);
        if (!base) {
            errno = EFAULT;
            return -1;
        }
        state->regions[state->region_count].base = base;
        state->regions[state->region_count].size = map_size;
        state->regions[state->region_count].fd = bpf_map__fd(map);
        ++state->region_count;
    }
    struct bpf_map* overflow = bpf_object__find_map_by_name(object, BPF_CAPSULE_MAP_HEAP_ARRAY);
    if (overflow) {
        state->overflow_fd = bpf_map__fd(overflow);
        state->overflow_value_size = bpf_map__value_size(overflow);
        state->overflow_entries = bpf_map__max_entries(overflow);
    }

    // Assemble the contiguous read view over the reservation the host baked
    // into the config before load: every region map lands at base +
    // region * REGION_SIZE, so a guest pointer is directly
    // dereferenceable for reading. The mapping is PROT_READ — host writes
    // must go through the copy helper, which maintains the cross-region
    // shadow suffix; a stray direct write faults instead of corrupting.
    // Direct pointer reads are part of this API, so failure at any step fails
    // the view instead of leaving a write-only partial interface.
    uintptr_t view_base = config->memory_view_base;
    if (!view_base) {
        // A zero base means bpf_capsule_configure() never ran; the object
        // itself refuses to execute in that state, so a memory view over it
        // is meaningless.
        errno = EINVAL;
        return -1;
    }
    {
        long view_page_result = sysconf(_SC_PAGESIZE);
        size_t view_page = view_page_result > 0 ? (size_t)view_page_result : 0;
        size_t overflow_stride = (state->overflow_value_size + 7u) & ~(size_t)7u;
        uint64_t total_regions = (uint64_t)state->region_count + state->overflow_entries;
        int usable = view_page && !(view_base & (view_page - 1u)) && !(overflow_stride & (view_page - 1u)) &&
            total_regions * BPF_CAPSULE_MEMORY_REGION_SIZE >= config->memory_end && view_base <= UINTPTR_MAX - total_regions * BPF_CAPSULE_MEMORY_REGION_SIZE;
        if (!usable) {
            errno = EFAULT;
        }
        uint8_t* view_at = (uint8_t*)view_base;
        uint64_t mapped_regions = 0;
        for (uint64_t region = 0; usable && region < total_regions; ++region) {
            int fd = region < state->region_count ? state->regions[region].fd : state->overflow_fd;
            off_t file_offset = region < state->region_count ? 0 : (off_t)((region - state->region_count) * overflow_stride);
            if (fd < 0) {
                errno = EFAULT;
                usable = 0;
            } else if (mmap(view_at + region * BPF_CAPSULE_MEMORY_REGION_SIZE, BPF_CAPSULE_MEMORY_REGION_SIZE, PROT_READ, MAP_SHARED | MAP_FIXED, fd,
                           file_offset) == MAP_FAILED) {
                usable = 0;
            } else {
                ++mapped_regions;
            }
        }
        if (usable && mprotect(view_at, view_page, PROT_NONE)) {
            usable = 0;
        }
        if (usable) {
            // Logical page zero holds no object; make null-plus-offset
            // dereferences fault like they should.
            state->view = view_at;
            state->view_size = (size_t)total_regions * BPF_CAPSULE_MEMORY_REGION_SIZE;
        } else {
            int saved_errno = errno;
            if (mapped_regions && __bpf_capsule_restore_reservation(view_at, (size_t)mapped_regions * BPF_CAPSULE_MEMORY_REGION_SIZE)) {
                return -1;
            }
            errno = saved_errno;
            return -1;
        }
    }
    state->config = config;
    return 0;
}

// Copy through a Capsule pointer without exposing whether this object uses a
// BPF arena or fixed-region maps. Direct reads are also valid. Copies into a
// Capsule pass here because the fixed backend maintains cross-region shadows.
static inline uint8_t* __bpf_capsule_fixed_region(
    const struct bpf_capsule_state* state, uint8_t* overflow_base, size_t overflow_stride, uint32_t region, size_t* size) {
    if (region < state->region_count) {
        *size = state->regions[region].size;
        return (uint8_t*)state->regions[region].base;
    }
    uint32_t overflow_region = region - state->region_count;
    if (overflow_base && overflow_region < state->overflow_entries) {
        *size = state->overflow_value_size;
        return overflow_base + (size_t)overflow_region * overflow_stride;
    }
    *size = 0;
    return NULL;
}

static int __bpf_capsule_memory_range(const struct bpf_capsule_state* state, const void* address, size_t size, uintptr_t* backing_offset) {
    const struct __bpf_capsule_object_config* config = state->config;
    uintptr_t pointer = (uintptr_t)address;
    uintptr_t offset;
    if (state->arena_base) {
        if (!state->arena_control || state->arena_control->ready != 2) {
            errno = EFAULT;
            return -1;
        }
        offset = pointer - state->arena_control->virtual_base;
    } else {
        offset = pointer - config->memory_view_base;
        if (offset > UINT32_MAX) {
            errno = EFAULT;
            return -1;
        }
    }

    uint64_t heap_end = config->heap_base + config->heap_bytes;
    if (heap_end < config->heap_base || config->stack_base < heap_end || config->memory_end < config->stack_base || offset < BPF_CAPSULE_ARENA_PAGE_SIZE ||
        offset >= config->memory_end || size > config->memory_end - offset ||
        (offset < config->stack_base && size > heap_end - (offset < heap_end ? offset : heap_end))) {
        errno = EFAULT;
        return -1;
    }

    if (state->arena_base) {
        offset = pointer - (uintptr_t)state->arena_base;
        if (offset >= state->arena_size || size > state->arena_size - offset) {
            errno = EFAULT;
            return -1;
        }
    }
    if (backing_offset) {
        *backing_offset = offset;
    }
    return 0;
}

static int __bpf_capsule_memory_copy(const struct bpf_capsule* capsule, void* destination, const void* source, size_t size, int write_to_capsule) {
    if (!size) {
        return 0;
    }
    const struct bpf_capsule_state* state = __bpf_capsule_state(capsule);
    const void* capsule_address = write_to_capsule ? destination : source;
    const void* host_buffer = write_to_capsule ? source : destination;
    if (!state || !state->config || !host_buffer) {
        errno = EINVAL;
        return -1;
    }
    uintptr_t offset;
    if (__bpf_capsule_memory_range(state, capsule_address, size, &offset)) {
        return -1;
    }

    if (state->arena_base) {
        uint8_t* base = (uint8_t*)state->arena_base;
        if (write_to_capsule) {
            memcpy(base + offset, source, size);
        } else {
            memcpy(destination, base + offset, size);
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
    if (state->overflow_fd >= 0 && state->overflow_entries) {
        long page_size_result = sysconf(_SC_PAGESIZE);
        size_t page_size = page_size_result > 0 ? (size_t)page_size_result : 0;
        overflow_stride = (state->overflow_value_size + 7u) & ~(size_t)7u;
        if (!page_size || overflow_stride < state->overflow_value_size || overflow_stride > SIZE_MAX / state->overflow_entries) {
            errno = EOVERFLOW;
            return -1;
        }
        size_t values_size = overflow_stride * state->overflow_entries;
        if (values_size > SIZE_MAX - (page_size - 1u)) {
            errno = EOVERFLOW;
            return -1;
        }
        overflow_size = (values_size + page_size - 1u) & ~(page_size - 1u);
        overflow_base = (uint8_t*)mmap(NULL, overflow_size, PROT_READ | PROT_WRITE, MAP_SHARED, state->overflow_fd, 0);
        if (overflow_base == MAP_FAILED) {
            return -1;
        }
    }

    uint64_t fixed_offset = offset;
    size_t remaining = size;
    size_t copied = 0;
    int error = 0;
    while (remaining) {
        uint32_t region = (uint32_t)(fixed_offset >> BPF_CAPSULE_MEMORY_REGION_SHIFT);
        size_t in_region = (size_t)fixed_offset & (BPF_CAPSULE_MEMORY_REGION_SIZE - 1);
        size_t part = BPF_CAPSULE_MEMORY_REGION_SIZE - in_region;
        if (part > remaining) {
            part = remaining;
        }
        size_t map_size = 0;
        uint8_t* base = __bpf_capsule_fixed_region(state, overflow_base, overflow_stride, region, &map_size);
        if (!base || in_region + part > map_size) {
            errno = EFAULT;
            error = -1;
            break;
        }
        if (write_to_capsule) {
            memcpy(base + in_region, (const uint8_t*)source + copied, part);
        } else {
            memcpy((uint8_t*)destination + copied, base + in_region, part);
        }

        // Old-kernel regions carry an eight-byte suffix mirroring the next
        // region so unaligned scalar loads can cross a verifier map boundary.
        // Refresh it whenever this write touches that next region's prefix.
        if (write_to_capsule && region && in_region < 8) {
            uint32_t previous_region = region - 1;
            size_t previous_size = 0;
            uint8_t* previous_base = __bpf_capsule_fixed_region(state, overflow_base, overflow_stride, previous_region, &previous_size);
            if (!previous_base || previous_size < BPF_CAPSULE_MEMORY_REGION_SIZE + 8 || map_size < 8) {
                errno = EFAULT;
                error = -1;
                break;
            }
            memcpy(previous_base + BPF_CAPSULE_MEMORY_REGION_SIZE, base, 8);
        }
        copied += part;
        fixed_offset += part;
        remaining -= part;
    }
    if (overflow_base) {
        munmap(overflow_base, overflow_size);
    }
    return error;
}

// Copy across a Capsule boundary. A destination in this Capsule's reserved
// window selects the write path; otherwise the source must be in the window
// and the copy reads out. Both pointers may belong to the same Capsule. Such a
// copy has memcpy's ordinary non-overlap requirement. The Capsule address may
// refer to the fiber-stack bank, so touching a live fiber's stack remains the
// caller's responsibility.
int bpf_capsule_memcpy(const struct bpf_capsule* capsule, void* destination, const void* source, size_t size) {
    if (!size) {
        return 0;
    }
    const struct bpf_capsule_state* state = __bpf_capsule_state(capsule);
    if (!state || !state->config || !destination || !source) {
        errno = EINVAL;
        return -1;
    }
    uintptr_t window = (uintptr_t)state->window;
    int destination_is_capsule = (uintptr_t)destination - window < BPF_CAPSULE_MEMORY_WINDOW_SIZE;
    int source_is_capsule = (uintptr_t)source - window < BPF_CAPSULE_MEMORY_WINDOW_SIZE;
    if (!destination_is_capsule && !source_is_capsule) {
        errno = EFAULT;
        return -1;
    }
    if (destination_is_capsule && source_is_capsule) {
        if (__bpf_capsule_memory_range(state, source, size, NULL)) {
            return -1;
        }
    }
    return __bpf_capsule_memory_copy(capsule, destination, source, size, destination_is_capsule);
}

int bpf_capsule_initialize(struct bpf_capsule* capsule) {
    struct bpf_capsule_state* state = __bpf_capsule_state(capsule);
    if (!capsule || !capsule->object || !state || !state->window) {
        errno = EINVAL;
        return -1;
    }
    struct bpf_object* object = capsule->object;
    struct bpf_program* initializer = bpf_object__find_program_by_name(object, BPF_CAPSULE_PROGRAM_INIT);
    if (initializer) {
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
    }
    if (__bpf_capsule_prepare_memory(capsule)) {
        return -1;
    }
    // Fixed tier: pointer-valued initializers are baked as bare window
    // displacements because the window base is load-time; the compiler
    // lists every such slot in .rodata.bpffix. Add the window to each slot
    // here, then publish readiness — capsule_call fails closed until this
    // word is set, which is what makes this verb mandatory on this tier
    // too. Idempotent: a second call observes the word and changes nothing.
    struct bpf_map* ready_map = bpf_object__find_map_by_name(object, BPF_CAPSULE_SECTION_READY);
    if (!ready_map) {
        return 0; // arena tier: readiness is the arena control word
    }
    size_t ready_size = 0;
    uint32_t* ready = (uint32_t*)bpf_map__initial_value(ready_map, &ready_size);
    if (!ready || ready_size < sizeof(*ready)) {
        errno = EFAULT;
        return -1;
    }
    if (*ready) {
        return 0;
    }
    uintptr_t window = state->config->memory_view_base;
    struct bpf_map* fixup_map = bpf_object__find_map_by_name(object, BPF_CAPSULE_SECTION_FIXUPS);
    if (fixup_map) {
        size_t table_bytes = 0;
        const uint64_t* slots = (const uint64_t*)bpf_map__initial_value(fixup_map, &table_bytes);
        if (!slots) {
            errno = EFAULT;
            return -1;
        }
        for (size_t i = 0; i < table_bytes / sizeof(uint64_t); ++i) {
            uintptr_t value = 0;
            memcpy(&value, (const void*)(window + slots[i]), sizeof(value));
            value += window;
            if (bpf_capsule_memcpy(capsule, (void*)(window + slots[i]), &value, sizeof(value))) {
                return -1;
            }
        }
    }
    *ready = 1;
    return 0;
}

// Observability over the view: the managed image's bounds in the external
// virtual address domain, and the host-reserved heap prefix selected at
// configure time. Capsule pointers are full virtual addresses on both
// tiers; on the arena tier the start is meaningful once
// bpf_capsule_initialize() has run (virtual_base reads as zero before
// then).
uint64_t bpf_capsule_memory_size(const struct bpf_capsule* capsule) {
    const struct bpf_capsule_state* state = __bpf_capsule_state(capsule);
    return state && state->config ? state->config->memory_end : 0;
}

const void* bpf_capsule_memory_start(const struct bpf_capsule* capsule) {
    const struct bpf_capsule_state* state = __bpf_capsule_state(capsule);
    if (!state || !state->config) {
        return 0;
    }
    // On the arena tier this is a full user virtual address: adding an
    // object offset yields exactly the pointer value the capsule itself
    // would hold, and (once the object is initialized) a pointer the host
    // can dereference through its own arena mapping.
    if (state->arena_control) {
        return (const void*)state->arena_control->virtual_base;
    }
    // Fixed tier: capsule pointers are base + offset and this is that base
    // (the window bpf_capsule_configure() reserved and baked).
    return (const void*)state->config->memory_view_base;
}

// The reserved prefix opens the heap: staging input there keeps it out of
// the allocator's reach for the object's whole lifetime, and both sides may
// pass pointers into it freely.
uint64_t bpf_capsule_memory_reserved_size(const struct bpf_capsule* capsule) {
    const struct bpf_capsule_state* state = __bpf_capsule_state(capsule);
    return state && state->config ? state->config->heap_reserved : 0;
}

void* bpf_capsule_memory_reserved_start(const struct bpf_capsule* capsule) {
    const struct bpf_capsule_state* state = __bpf_capsule_state(capsule);
    if (!state || !state->config) {
        return 0;
    }
    uintptr_t base = state->config->heap_base;
    if (state->arena_control) {
        return (void*)(state->arena_control->virtual_base + base);
    }
    return (void*)(state->config->memory_view_base + base);
}
