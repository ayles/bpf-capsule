// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
// The complete guest-side Capsule API — the only header BPF program code
// includes, in any translation unit. The runtime behind it
// (src/runtime/guest/bpf_capsule.c) is compiled into the object by the build
// pipeline automatically.
//
// Native boundary — usable in ordinary verifier-native entry code:
//
//   capsule_call(&out, root, args...)   start managed execution of root
//   capsule_call_void(root, args...)    same, for a void root
//   capsule_continue(&out, cont)        resume a PENDING/YIELD computation
//   capsule_continue_void(cont)         same, for a void root
//   capsule_reset(cont)                 cancel it and release the fiber
//
// Managed code — usable only inside Capsule-managed functions:
//
//   capsule_fiber_index()               this computation's fiber index
//   capsule_fiber_count()               load-time-selected fiber count
//   capsule_heap_start(), capsule_heap_size()   the allocation pool
//   capsule_exit(code)                  end the computation like exit(), noreturn
//   capsule_yield()                     suspend back to the native caller
//   capsule_borrowed_ctx()              the entry's borrowed verifier context
//
// BPF_CAPSULE_MAX_FIBERS is the compile-time active-fiber ceiling.
//
// Statuses, error codes, and struct capsule_result are in
// bpf_capsule_types.h; the host-side API is bpf_capsule_host.h. Names under
// `bpf_capsule_*`, `__bpf_capsule_*`, and `bpf_heap_*` belong to the runtime
// and compiler; everything `capsule_*` here is the public API.
#pragma once

#include "bpf_capsule_types.h"

// Prove this function and everything it calls suspension-free, and compile
// it as one ordinary BPF subprogram: no fiber, no dispatch regions, plain
// call cost from managed code, and the whole call completes within a
// single BPF invocation (safe to hold a lock across it - this is how the
// runtime allocator takes its lease). The proof is enforced, not assumed:
// loops need exact constant trip counts, calls must be direct and
// resolved, and the body and native frame must fit their budgets; a
// function that cannot be proven fails the build naming the reason.
// Implies noinline so the proven body is the one that executes.
#define CAPSULE_NOSUSPEND __attribute__((annotate("capsule.nosuspend"), noinline))

// Compile-time verifier/control bound. One portable object chooses its actual
// fiber count after open and before load; unused fiber stacks are not backed.
#ifndef BPF_CAPSULE_MAX_FIBERS
#define BPF_CAPSULE_MAX_FIBERS 512
#endif
#if BPF_CAPSULE_MAX_FIBERS < 1
#error "BPF_CAPSULE_MAX_FIBERS must be at least one"
#endif
#if BPF_CAPSULE_MAX_FIBERS > BPF_CAPSULE_MAX_FIBERS_LIMIT
#error "BPF_CAPSULE_MAX_FIBERS must fit in the continuation's 16-bit fiber field"
#endif

// Every marker below is matched by the compiler by its exact C name; C++
// translation units need unmangled linkage for them.
#ifdef __cplusplus
extern "C" {
#endif

// Valid only in Capsule-managed code. The compiler replaces this marker with
// the ID already carried by the physical step; querying it performs no map or
// helper lookup. Ordinary arrays indexed by this value are fiber-local
// storage without a separate TLS memory model.
extern uint32_t __bpf_capsule_current_fiber_index(void);
static __attribute__((always_inline)) inline uint32_t capsule_fiber_index(void) {
    return __bpf_capsule_current_fiber_index();
}

// Load-time-selected number of fibers. The compiler replaces this marker with
// a bounded read of the object configuration, so managed loops execute only
// for active fibers while BPF_CAPSULE_MAX_FIBERS remains their verifier proof.
extern uint32_t __bpf_capsule_active_fiber_count(void);
static __attribute__((always_inline)) inline uint32_t capsule_fiber_count(void) {
    return __bpf_capsule_active_fiber_count();
}

// One load-time-sized allocation pool in Capsule's unified address space.
// Freestanding support libraries use this to initialize their allocator;
// applications may use it to install another allocator. If the host reserved
// a staging prefix, these accessors expose only the suffix after that aligned
// prefix; pointers into the reserved prefix remain valid Capsule memory but
// are not part of the managed allocation pool.
extern void* __bpf_capsule_heap_start(void);
extern uint64_t __bpf_capsule_heap_size(void);
static __attribute__((always_inline)) inline void* capsule_heap_start(void) {
    return __bpf_capsule_heap_start();
}
static __attribute__((always_inline)) inline uint64_t capsule_heap_size(void) {
    return __bpf_capsule_heap_size();
}

// The single termination primitive. The compiler lowers it to a nonlocal
// stop that publishes the code and unwinds the software stack; the caller
// observes CAPSULE_EXITED with the code in capsule_result.code. Negative
// codes are the framework's — only the compiler and runtime pass them.
extern void __bpf_capsule_exit(int32_t code);

// End the computation the way exit() ends a process. The observed code is
// masked with 0xff exactly as POSIX observes an exit status, so 0..255 is
// the guest's code space and can never collide with the framework's
// negative codes. Valid only in Capsule-managed code. This is a nonlocal
// stop: no atexit handlers or destructors run, the computation stops, and
// the fiber is released.
static __attribute__((always_inline, noreturn)) inline void capsule_exit(int code) {
    __bpf_capsule_exit(code & 0xff);
    __builtin_unreachable();
}

// Voluntarily return control to the native eBPF caller without completing the
// computation. The caller observes status CAPSULE_YIELD with a continuation
// that must be passed to exactly one later capsule_continue (resumes
// immediately after this call) or capsule_reset (cancels and releases the
// fiber). Request and response data are an application protocol; the Capsule
// runtime only reports the suspension.
extern void __bpf_capsule_yield(void);
static __attribute__((always_inline)) inline void capsule_yield(void) {
    __bpf_capsule_yield();
}

// Valid only in Capsule-managed code, in an object whose root borrows the
// entry's verifier context. Returns the live borrowed context; cast it to
// your entry's context type. The compiler threads the context through every
// physical step and this marker reads it without ever storing the pointer,
// so its verifier identity is preserved. The usual lifetime rules apply
// unchanged: values derived from the context do not survive a suspension
// point — re-derive them after any call that may suspend.
extern void* __bpf_capsule_current_ctx(void);
static __attribute__((always_inline)) inline void* capsule_borrowed_ctx(void) {
    return __bpf_capsule_current_ctx();
}

// ------------------------------------------------------------ native boundary
//
// Starting a call leases its execution state. Completed work returns the
// slot immediately; pending or voluntarily yielded work returns the opaque
// continuation needed by continue or reset. Every termination reclaims the
// slot; pool exhaustion is an ordinary CAPSULE_EXITED with the framework's
// negative code and no continuation. The output is written only on
// CAPSULE_OK — a terminated guest never returned a value, so CAPSULE_EXITED
// carries result.code (0..255 the guest's exit status, negative the
// framework's) and leaves the output untouched. The output type must exactly
// match the root return type; use capsule_call_void for void roots.
//
// Concurrent entry invocations may capsule_call at the same time; each
// successful call leases a distinct fiber. A continuation is not CPU-bound
// and may be resumed by another entry invocation or CPU, but it remains a
// single-consumer handle: concurrent use of copied tokens is invalid and the
// runtime atomically accepts at most one consumer.
//
// capsule_continue resumes a PENDING or YIELD computation by its
// continuation. Each continuation is single-use: pass it to exactly one
// capsule_continue or capsule_reset, and use only the newest continuation a
// fiber has reported. The token carries a lease generation, so a duplicate or
// delayed value is rejected even after its fiber has been re-leased to
// unrelated work. The output pointer must have the root's exact return size: a size mismatch reports
// CAPSULE_ERROR_RETURN_MISMATCH and cancels the computation, releasing the
// fiber.
//
// capsule_reset cancels a PENDING or YIELD computation and releases its
// fiber without running it further. Returns CAPSULE_OK on success; the
// continuation is consumed either way. This is the only way to reclaim a
// fiber whose work will never be resumed — dropping a continuation without
// resetting leaks the fiber until the object is reloaded.
// Nothing user-serviceable below: the machinery the macros above expand to,
// defined by the runtime (bpf_capsule.c) and resolved at the whole-program
// bitcode link.
#define __BPF_CAPSULE_NO_FIBER (~0u)

extern int __bpf_capsule_plan_broken(void);
extern uint32_t __bpf_capsule_fiber_acquire(void);
extern int __bpf_capsule_fiber_release(uint32_t fiber);
extern uint64_t __bpf_capsule_make_continuation(uint32_t fiber);
extern void __bpf_capsule_finish_exited(struct capsule_result* result, uint32_t fiber);
extern int __bpf_capsule_call(uint32_t fiber, void* output, uint64_t output_size, uint64_t output_alignment, void* function, ...);
extern struct capsule_result __bpf_capsule_continue(void* output, uint64_t output_size, uint64_t output_alignment, uint64_t continuation)
    __attribute__((warn_unused_result));
extern struct capsule_result __bpf_capsule_reset(uint64_t continuation) __attribute__((warn_unused_result));

static __attribute__((always_inline, warn_unused_result)) inline struct capsule_result __bpf_capsule_result_must_be_used(struct capsule_result result) {
    return result;
}

#ifdef __cplusplus
#define __BPF_CAPSULE_AUTO auto
#define __BPF_CAPSULE_ALIGNOF(type) alignof(type)
// LLVM's opaque pointers erase the destination's C++ pointee type before the
// partition pass. Size/alignment are still checked there; normal C++ call
// checking validates the arguments. C gets the stronger exact-type assertion
// below because Clang exposes __builtin_types_compatible_p only in C mode.
#define __BPF_CAPSULE_CHECK_RETURN(output, function, ...)
#define __BPF_CAPSULE_CHECK_VOID(function, ...) static_assert(__is_void(__typeof__((function)(__VA_ARGS__))), "capsule_call_void requires a void function")
#else
#define __BPF_CAPSULE_AUTO __auto_type
#define __BPF_CAPSULE_ALIGNOF(type) _Alignof(type)
#define __BPF_CAPSULE_CHECK_RETURN(output, function, ...) \
    _Static_assert( \
        __builtin_types_compatible_p(__typeof__(*(output)), __typeof__((function)(__VA_ARGS__))), "capsule_call output must match the function return type")
#define __BPF_CAPSULE_CHECK_VOID(function, ...) \
    _Static_assert(__builtin_types_compatible_p(__typeof__((function)(__VA_ARGS__)), void), "capsule_call_void requires a void function")
#endif

#define __bpf_capsule_begin(output, output_size, output_alignment, function, ...) \
    __bpf_capsule_result_must_be_used(({ \
        int __capsule_broken = __bpf_capsule_plan_broken(); \
        uint32_t __capsule_fiber = __capsule_broken ? __BPF_CAPSULE_NO_FIBER : __bpf_capsule_fiber_acquire(); \
        struct capsule_result __capsule_result = { \
            __capsule_broken ? CAPSULE_ERROR_BAD_PLAN : CAPSULE_ERROR_POOL_EXHAUSTED, CAPSULE_EXITED, BPF_CAPSULE_NO_CONTINUATION}; \
        if (__capsule_fiber != __BPF_CAPSULE_NO_FIBER) { \
            __capsule_result.code = 0; \
            __capsule_result.status = \
                __bpf_capsule_call(__capsule_fiber, (void*)(output), (output_size), (output_alignment), (void*)(function), ##__VA_ARGS__); \
            if (__capsule_result.status == CAPSULE_OK) { \
                if (__bpf_capsule_fiber_release(__capsule_fiber)) { \
                    __capsule_result.status = CAPSULE_EXITED; \
                    __capsule_result.code = CAPSULE_ERROR_POOL_CORRUPT; \
                } \
            } else if (__capsule_result.status == CAPSULE_EXITED) { \
                __bpf_capsule_finish_exited(&__capsule_result, __capsule_fiber); \
            } else { \
                __capsule_result.continuation = __bpf_capsule_make_continuation(__capsule_fiber); \
            } \
        } \
        __capsule_result; \
    }))

#define capsule_call(output, function, ...) \
    ({ \
        __BPF_CAPSULE_AUTO __capsule_output = (output); \
        __BPF_CAPSULE_CHECK_RETURN(__capsule_output, function, ##__VA_ARGS__); \
        __bpf_capsule_begin(__capsule_output, sizeof(*__capsule_output), __BPF_CAPSULE_ALIGNOF(__typeof__(*__capsule_output)), function, ##__VA_ARGS__); \
    })

#define capsule_call_void(function, ...) \
    ({ \
        __BPF_CAPSULE_CHECK_VOID(function, ##__VA_ARGS__); \
        __bpf_capsule_begin((void*)0, 0, 1, function, ##__VA_ARGS__); \
    })

#define capsule_continue(output, continuation) \
    __bpf_capsule_result_must_be_used(({ \
        __BPF_CAPSULE_AUTO __capsule_output = (output); \
        __bpf_capsule_continue((void*)__capsule_output, sizeof(*__capsule_output), __BPF_CAPSULE_ALIGNOF(__typeof__(*__capsule_output)), (continuation)); \
    }))

#define capsule_continue_void(continuation) __bpf_capsule_result_must_be_used(__bpf_capsule_continue((void*)0, 0, 1, (continuation)))

#define capsule_reset(continuation) __bpf_capsule_result_must_be_used(__bpf_capsule_reset((continuation)))

#ifdef __cplusplus
}
#endif
