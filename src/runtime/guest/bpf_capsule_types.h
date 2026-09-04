// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#pragma once

#include <stdint.h>

// Types shared by guest entry code, application control records, and hosts.
#define BPF_CAPSULE_NO_CONTINUATION UINT64_MAX
#define BPF_CAPSULE_MAX_FIBERS_LIMIT UINT16_MAX

enum capsule_status {
    CAPSULE_OK = 0,
    CAPSULE_PENDING = 1,
    CAPSULE_YIELD = 2,
    CAPSULE_EXITED = 3,
};

// Guest exit statuses occupy 0..255. Negative values mean the framework
// stopped the computation; bpf_capsule_error_string() describes them.
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
#define CAPSULE_ERROR_UNREACHABLE (-13)
#define CAPSULE_ERROR_TRAP (-14)
#define CAPSULE_ERROR_ALLOCATOR_CORRUPT (-16)
#define CAPSULE_ERROR_BAD_PLAN (-17)

struct capsule_result {
    int32_t code;
    enum capsule_status status;
    uint64_t continuation;
};

#ifdef __cplusplus
#define __BPF_CAPSULE_TYPES_ASSERT(condition, message) static_assert(condition, message)
#else
#define __BPF_CAPSULE_TYPES_ASSERT(condition, message) _Static_assert(condition, message)
#endif

__BPF_CAPSULE_TYPES_ASSERT(sizeof(enum capsule_status) == 4, "capsule_status width ABI");
__BPF_CAPSULE_TYPES_ASSERT(__builtin_offsetof(struct capsule_result, code) == 0, "capsule_result.code ABI");
__BPF_CAPSULE_TYPES_ASSERT(__builtin_offsetof(struct capsule_result, status) == 4, "capsule_result.status ABI");
__BPF_CAPSULE_TYPES_ASSERT(__builtin_offsetof(struct capsule_result, continuation) == 8, "capsule_result.continuation ABI");
__BPF_CAPSULE_TYPES_ASSERT(sizeof(struct capsule_result) == 16, "capsule_result size ABI");

#undef __BPF_CAPSULE_TYPES_ASSERT
