// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
// The synchronized TLSF allocator over Capsule's load-time-sized heap.
#include "bpf_capsule.h"

#include <errno.h>
#include <malloc.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

// ------------------------------------------------------------------ allocator
//
// Allocation uses the fetched upstream TLSF implementation: two-level
// segregated fit and O(1) malloc/free over the load-time-sized Capsule heap.
#include "tlsf.h"

#ifndef BPF_CAPSULE_FEATURE_FULL_ATOMICS
#define BPF_CAPSULE_FEATURE_FULL_ATOMICS 0
#endif

// bpf-capsule-ld checks this build marker against --allocator-lock before it
// transforms the image. It is otherwise dead after whole-program linking.
const unsigned int __bpf_capsule_allocator_lock_mode = BPF_CAPSULE_FEATURE_FULL_ATOMICS;

static tlsf_t fs_tlsf;

// Modern BPF JITs implement compare-exchange. Keep the mutex in native map
// storage so taking it is one BPF atomic rather than a HASH update followed
// by a HASH delete for every allocator operation. It cannot live in Capsule
// memory: managed compare-exchange is deliberately unsupported.
#if BPF_CAPSULE_FEATURE_FULL_ATOMICS
static volatile unsigned int fs_allocator_lock_word SEC(".bss.fsalloc");
#else
// Linux 5.15 verifies the modern atomic encodings but old arm64 JITs only
// implement non-fetching XADD and otherwise fall the complete program back to
// the interpreter. A single-entry HASH is the kernel's native atomic
// test-and-set on that tier. This cost stays entirely at allocator entry/exit;
// generated application code and memory accesses are unchanged.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1);
    __type(key, unsigned int);
    __type(value, unsigned int);
} fs_allocator_lease SEC(".maps");
#endif

#define FS_ALLOCATOR_BUSY (~0ull)
#define FS_ALLOCATOR_ERROR (~1ull)

static __attribute__((always_inline)) int fs_try_lock(void) {
#if BPF_CAPSULE_FEATURE_FULL_ATOMICS
    unsigned int expected = 0;
    return __atomic_compare_exchange_n(&fs_allocator_lock_word, &expected, 1, 0, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST);
#else
    unsigned int key = 0;
    unsigned int value = 1;
    return bpf_map_update_elem(&fs_allocator_lease, &key, &value, BPF_NOEXIST) == 0;
#endif
}

static __attribute__((always_inline)) int fs_unlock(void) {
#if BPF_CAPSULE_FEATURE_FULL_ATOMICS
    return __atomic_exchange_n(&fs_allocator_lock_word, 0, __ATOMIC_SEQ_CST) == 1;
#else
    unsigned int key = 0;
    return bpf_map_delete_elem(&fs_allocator_lease, &key) == 0;
#endif
}

static __attribute__((always_inline)) int fs_setup(void) {
    size_t heap_size = capsule_heap_size();
    size_t minimum = tlsf_size() + tlsf_pool_overhead() + tlsf_block_size_min();
    if (heap_size < minimum) {
        return 0;
    }
    fs_tlsf = tlsf_create_with_pool(capsule_heap_start(), heap_size);
    return fs_tlsf != 0;
}

// These four scalar-ABI operations are compiler-enforced no-suspend islands.
// A busy lease returns without touching TLSF; the ordinary managed wrapper
// retries and may suspend there. Once an island acquires the lease it performs
// the complete metadata operation and releases it in the same BPF invocation.
// The compiler rejects any virtualized backedge or managed call that survives
// inside a CAPSULE_NOSUSPEND function.
CAPSULE_NOSUSPEND uint64_t __bpf_allocator_malloc(size_t n) {
    if (!fs_try_lock()) {
        return FS_ALLOCATOR_BUSY;
    }
    if (!fs_tlsf && !fs_setup()) {
        return fs_unlock() ? 0 : FS_ALLOCATOR_ERROR;
    }
    void* result = tlsf_malloc(fs_tlsf, n);
    return fs_unlock() ? (uint64_t)(uintptr_t)result : FS_ALLOCATOR_ERROR;
}

CAPSULE_NOSUSPEND uint64_t __bpf_allocator_free(uintptr_t address) {
    if (!fs_try_lock()) {
        return FS_ALLOCATOR_BUSY;
    }
    if (fs_tlsf) {
        tlsf_free(fs_tlsf, (void*)address);
    }
    return fs_unlock() ? 0 : FS_ALLOCATOR_ERROR;
}

CAPSULE_NOSUSPEND uint64_t __bpf_allocator_size(uintptr_t address) {
    if (!fs_try_lock()) {
        return FS_ALLOCATOR_BUSY;
    }
    size_t result = fs_tlsf ? tlsf_block_size((void*)address) : 0;
    return fs_unlock() ? result : FS_ALLOCATOR_ERROR;
}

CAPSULE_NOSUSPEND uint64_t __bpf_allocator_memalign(size_t align, size_t n) {
    if (!fs_try_lock()) {
        return FS_ALLOCATOR_BUSY;
    }
    if (!fs_tlsf && !fs_setup()) {
        return fs_unlock() ? 0 : FS_ALLOCATOR_ERROR;
    }
    void* result = tlsf_memalign(fs_tlsf, align, n);
    return fs_unlock() ? (uint64_t)(uintptr_t)result : FS_ALLOCATOR_ERROR;
}

void* malloc(size_t n) {
    uint64_t result;
    do {
        result = __bpf_allocator_malloc(n);
    } while (result == FS_ALLOCATOR_BUSY);
    if (result == FS_ALLOCATOR_ERROR) {
        __bpf_capsule_exit(CAPSULE_ERROR_ALLOCATOR_CORRUPT);
    }
    if (!result) {
        errno = ENOMEM;
    }
    return (void*)(uintptr_t)result;
}

void free(void* p) {
    if (!p) {
        return;
    }
    uint64_t result;
    do {
        result = __bpf_allocator_free((uintptr_t)p);
    } while (result == FS_ALLOCATOR_BUSY);
    if (result == FS_ALLOCATOR_ERROR) {
        __bpf_capsule_exit(CAPSULE_ERROR_ALLOCATOR_CORRUPT);
    }
}

__attribute__((no_builtin("calloc"))) void* calloc(size_t n, size_t sz) {
    if (sz && n > SIZE_MAX / sz) {
        errno = ENOMEM;
        return 0;
    }
    size_t total = n * sz;
    void* p = malloc(total);
    if (p) {
        memset(p, 0, total);
    }
    return p;
}

size_t malloc_usable_size(void* p) {
    if (!p) {
        return 0;
    }
    uint64_t result;
    do {
        result = __bpf_allocator_size((uintptr_t)p);
    } while (result == FS_ALLOCATOR_BUSY);
    if (result == FS_ALLOCATOR_ERROR) {
        __bpf_capsule_exit(CAPSULE_ERROR_ALLOCATOR_CORRUPT);
    }
    return result;
}

void* realloc(void* p, size_t n) {
    if (!p) {
        return malloc(n);
    }
    if (!n) {
        free(p);
        return 0;
    }
    size_t old_size = malloc_usable_size(p);
    if (old_size >= n) {
        return p;
    }
    void* replacement = malloc(n);
    if (!replacement) {
        return 0;
    }
    memcpy(replacement, p, old_size);
    free(p);
    return replacement;
}

// malloc's blocks are 8-byte aligned; callers with stricter needs (Rust's
// GlobalAlloc contract, for one) go through TLSF's aligned path. The result
// is an ordinary block, so free() takes it back like any other.
void* memalign(size_t align, size_t n) {
    if (!align || (align & (align - 1))) {
        errno = EINVAL;
        return 0;
    }
    if (align > tlsf_block_size_max()) {
        errno = ENOMEM;
        return 0;
    }
    uint64_t result;
    do {
        result = __bpf_allocator_memalign(align, n);
    } while (result == FS_ALLOCATOR_BUSY);
    if (result == FS_ALLOCATOR_ERROR) {
        __bpf_capsule_exit(CAPSULE_ERROR_ALLOCATOR_CORRUPT);
    }
    if (!result) {
        errno = ENOMEM;
    }
    return (void*)(uintptr_t)result;
}

void* aligned_alloc(size_t align, size_t n) {
    if (!align || n % align) {
        errno = EINVAL;
        return 0;
    }
    return memalign(align, n);
}

int posix_memalign(void** result, size_t align, size_t n) {
    if (!align || (align & (align - 1)) || align % sizeof(void*)) {
        return EINVAL;
    }
    int saved_errno = errno;
    void* allocation = memalign(align, n);
    int error = allocation ? 0 : errno == EINVAL ? EINVAL : ENOMEM;
    errno = saved_errno;
    if (!error) {
        *result = allocation;
    }
    return error;
}
