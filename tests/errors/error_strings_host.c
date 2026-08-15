// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#include <stdio.h>
#include <string.h>

#include "bpf_capsule_host.h"

struct named_status {
    unsigned int value;
    const char* name;
};

struct named_code {
    int64_t value;
    const char* name;
};

int main(void) {
    static const struct named_status statuses[] = {
        {CAPSULE_OK, "ok"},
        {CAPSULE_PENDING, "pending"},
        {CAPSULE_YIELD, "yield"},
        {CAPSULE_EXITED, "exited"},
        {99, "unknown status"},
    };
    static const struct named_code codes[] = {
        {CAPSULE_ERROR_POOL_EXHAUSTED, "fiber pool exhausted"},
        {CAPSULE_ERROR_INVALID_CONTINUATION, "invalid continuation"},
        {CAPSULE_ERROR_STALE_CONTINUATION, "stale continuation"},
        {CAPSULE_ERROR_NOT_PENDING, "continuation is not pending"},
        {CAPSULE_ERROR_POOL_CORRUPT, "fiber pool corrupt"},
        {CAPSULE_ERROR_RETURN_MISMATCH, "return value layout mismatch"},
        {CAPSULE_ERROR_STACK_OVERFLOW, "fiber stack overflow"},
        {CAPSULE_ERROR_MEMORY_FAULT, "capsule memory fault"},
        {CAPSULE_ERROR_INVALID_DISPATCH, "invalid managed dispatch"},
        {CAPSULE_ERROR_INTRINSIC_GUARD, "unlowered compiler intrinsic"},
        {CAPSULE_ERROR_UNSUPPORTED_FP_INTRINSIC, "unsupported floating-point intrinsic"},
        {CAPSULE_ERROR_VLA_BOUNDS, "variable-length array bound exceeded"},
        {CAPSULE_ERROR_UNREACHABLE, "unreachable code executed"},
        {CAPSULE_ERROR_TRAP, "trap executed"},
        {CAPSULE_ERROR_UNSUPPORTED_LIBC, "unsupported libc operation"},
        {CAPSULE_ERROR_ALLOCATOR_CORRUPT, "allocator state corrupt"},
        {CAPSULE_ERROR_BAD_PLAN, "loader applied an incomplete configuration plan"},
        // Non-negative codes are the guest's own exit statuses; the framework
        // has no name for them beyond the shared fallback.
        {0, "guest exit status"},
        {1, "guest exit status"},
        {255, "guest exit status"},
        {0x123456789abcdefll, "guest exit status"},
        // Negative codes outside the defined set are unknown framework codes.
        {-9999, "unknown framework code"},
        {(int64_t)0x8000000000000000ull, "unknown framework code"},
    };

    for (unsigned int i = 0; i < sizeof(statuses) / sizeof(statuses[0]); ++i) {
        if (strcmp(bpf_capsule_status_string(statuses[i].value), statuses[i].name)) {
            return 1;
        }
    }
    for (unsigned int i = 0; i < sizeof(codes) / sizeof(codes[0]); ++i) {
        if (strcmp(bpf_capsule_error_string(codes[i].value), codes[i].name)) {
            return 1;
        }
    }
    struct capsule_result exited = {
        .code = -37,
        .status = CAPSULE_EXITED,
        .reserved = 0,
        .continuation = BPF_CAPSULE_NO_CONTINUATION,
    };
    if (exited.code != -37 || exited.reserved != 0 || exited.continuation != BPF_CAPSULE_NO_CONTINUATION || sizeof(exited) != 24) {
        return 1;
    }

    struct __bpf_capsule_object_config config = {
        .heap_base = 0x10000,
        .heap_bytes = 0x100000,
        .fiber_count = 1,
        .stack_bytes_per_fiber = 0x40000,
        .max_fibers = 4,
        .arena_image_pages = 1,
        .uses_arena = 1,
        .abi_magic = BPF_CAPSULE_ABI_MAGIC,
        .abi_version = BPF_CAPSULE_ABI_VERSION,
    };
    uint32_t entries = 0;
    struct bpf_capsule_config requested = {.fiber_count = 2, .heap_bytes = 0x200000, .reserved_bytes = 17};
    unsigned char short_config[sizeof(config) - 1] = {0};
    struct __bpf_capsule_object_config untouched;
    memset(&untouched, 0xa5, sizeof(untouched));
    struct __bpf_capsule_object_config before = untouched;
    errno = 0;
    if (!__bpf_capsule_copy_plan(short_config, sizeof(short_config), requested, &untouched, &entries) || errno != ENOENT ||
        memcmp(&untouched, &before, sizeof(untouched))) {
        return 1;
    }
    if (__bpf_capsule_plan(&config, sizeof(config), requested, &entries) || config.fiber_count != 2 || config.heap_reserved != 32 || !entries) {
        return 1;
    }
    config.abi_version++;
    errno = 0;
    if (!__bpf_capsule_plan(&config, sizeof(config), requested, &entries) || errno != EINVAL) {
        return 1;
    }
    puts("ERROR-STRINGS-PASS");
    return 0;
}
