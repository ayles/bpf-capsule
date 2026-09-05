// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <stdatomic.h>

#include "bpf_capsule.h"

#include "native.h"

volatile struct atomic_runtime_values atomic_runtime_values SEC(".data.atomrun") = {
    .word = ATOMIC_RUNTIME_INITIAL_WORD,
    .doubleword = ATOMIC_RUNTIME_INITIAL_DOUBLEWORD,
};

struct atomic_managed_cells {
    _Atomic unsigned char byte;
    unsigned char byte_padding;
    _Atomic unsigned short half;
    _Atomic unsigned int word;
    _Atomic uint64_t doubleword;
};

// Keep these cells in Capsule memory and reach them through a stored pointer.
static struct atomic_managed_cells atomic_managed_cells = {
    .byte = ATOMIC_MANAGED_BYTE_A,
    .half = ATOMIC_MANAGED_HALF_A,
    .word = ATOMIC_MANAGED_WORD_A,
    .doubleword = ATOMIC_MANAGED_DOUBLEWORD_A,
};
static struct atomic_managed_cells* volatile atomic_managed_pointer = &atomic_managed_cells;

volatile struct atomic_managed_result atomic_managed_result SEC(".data.atommanaged");

#define ATOMIC_MANAGED_ITERATIONS 8192u

static void atomic_managed_writer_body(void) {
    struct atomic_managed_cells* cells = atomic_managed_pointer;
    for (unsigned int iteration = 0; iteration < ATOMIC_MANAGED_ITERATIONS; ++iteration) {
        unsigned int alternate = iteration & 1u;
        atomic_store_explicit(&cells->byte, alternate ? ATOMIC_MANAGED_BYTE_B : ATOMIC_MANAGED_BYTE_A, memory_order_relaxed);
        atomic_store_explicit(&cells->half, alternate ? ATOMIC_MANAGED_HALF_B : ATOMIC_MANAGED_HALF_A, memory_order_relaxed);
        atomic_store_explicit(&cells->word, alternate ? ATOMIC_MANAGED_WORD_B : ATOMIC_MANAGED_WORD_A, memory_order_relaxed);
        atomic_store_explicit(&cells->doubleword, alternate ? ATOMIC_MANAGED_DOUBLEWORD_B : ATOMIC_MANAGED_DOUBLEWORD_A, memory_order_relaxed);
    }
    atomic_managed_result.writer_failures = 0;
}

static void atomic_managed_reader_body(void) {
    struct atomic_managed_cells* cells = atomic_managed_pointer;
    uint64_t failures = 0;
    for (unsigned int iteration = 0; iteration < ATOMIC_MANAGED_ITERATIONS; ++iteration) {
        unsigned char byte = atomic_load_explicit(&cells->byte, memory_order_relaxed);
        unsigned short half = atomic_load_explicit(&cells->half, memory_order_relaxed);
        unsigned int word = atomic_load_explicit(&cells->word, memory_order_relaxed);
        uint64_t doubleword = atomic_load_explicit(&cells->doubleword, memory_order_relaxed);
        if (byte != ATOMIC_MANAGED_BYTE_A && byte != ATOMIC_MANAGED_BYTE_B) {
            failures |= 4;
        }
        if (half != ATOMIC_MANAGED_HALF_A && half != ATOMIC_MANAGED_HALF_B) {
            failures |= 8;
        }
        if (word != ATOMIC_MANAGED_WORD_A && word != ATOMIC_MANAGED_WORD_B) {
            failures |= 16;
        }
        if (doubleword != ATOMIC_MANAGED_DOUBLEWORD_A && doubleword != ATOMIC_MANAGED_DOUBLEWORD_B) {
            failures |= 32;
        }
    }
    atomic_managed_result.reader_failures = failures;
}

#if BPF_CAPSULE_TEST_MANAGED_RMW
static _Atomic uint64_t atomic_managed_counter;

static void atomic_managed_rmw_body(void) {
    struct atomic_managed_cells* cells = atomic_managed_pointer;
    uint64_t failures = 0;

    _Atomic unsigned char* byte = &cells->byte;
    _Atomic unsigned short* half = &cells->half;
    _Atomic unsigned int* word = &cells->word;
    _Atomic uint64_t* doubleword = &cells->doubleword;

    atomic_store_explicit(byte, 3, memory_order_seq_cst);
    if (atomic_fetch_add_explicit(byte, 4, memory_order_seq_cst) != 3 || atomic_load_explicit(byte, memory_order_acquire) != 7) {
        failures |= 1;
    }

    atomic_store_explicit(half, 0x1200, memory_order_release);
    if (atomic_fetch_or_explicit(half, 0x34, memory_order_seq_cst) != 0x1200) {
        failures |= 2;
    }
    unsigned short expected_half = 0x1234;
    if (!atomic_compare_exchange_strong_explicit(half, &expected_half, 0xabcd, memory_order_acq_rel, memory_order_acquire) || expected_half != 0x1234) {
        failures |= 4;
    }

    atomic_store_explicit(word, 0xff00ff00u, memory_order_seq_cst);
    if (atomic_fetch_and_explicit(word, 0x0ffff0ffu, memory_order_seq_cst) != 0xff00ff00u || atomic_load_explicit(word, memory_order_relaxed) != 0x0f00f000u) {
        failures |= 8;
    }
    if (atomic_fetch_sub_explicit(word, 0x1000u, memory_order_acq_rel) != 0x0f00f000u ||
        atomic_fetch_xor_explicit(word, 0x00ff00ffu, memory_order_seq_cst) != 0x0f00e000u || atomic_load_explicit(word, memory_order_relaxed) != 0x0fffe0ffu) {
        failures |= 64;
    }

    atomic_store_explicit(doubleword, 41, memory_order_seq_cst);
    if (atomic_fetch_add_explicit(doubleword, 1, memory_order_seq_cst) != 41 || atomic_exchange_explicit(doubleword, 99, memory_order_seq_cst) != 42) {
        failures |= 16;
    }

    _Atomic(struct atomic_managed_cells*) pointer = NULL;
    atomic_store_explicit(&pointer, cells, memory_order_release);
    if (atomic_load_explicit(&pointer, memory_order_acquire) != cells) {
        failures |= 32;
    }
    struct atomic_managed_cells* expected_pointer = cells;
    if (!atomic_compare_exchange_strong_explicit(&pointer, &expected_pointer, NULL, memory_order_acq_rel, memory_order_acquire) || expected_pointer != cells) {
        failures |= 128;
    }
    expected_pointer = cells;
    if (atomic_compare_exchange_weak_explicit(&pointer, &expected_pointer, cells, memory_order_acq_rel, memory_order_relaxed) || expected_pointer != NULL) {
        failures |= 256;
    }

    atomic_flag flag = ATOMIC_FLAG_INIT;
    atomic_flag_clear_explicit(&flag, memory_order_release);
    if (atomic_flag_test_and_set_explicit(&flag, memory_order_acquire) || !atomic_flag_test_and_set_explicit(&flag, memory_order_seq_cst)) {
        failures |= 512;
    }
    atomic_thread_fence(memory_order_seq_cst);
    atomic_signal_fence(memory_order_acq_rel);
    atomic_managed_result.rmw_failures = failures;
}

static void atomic_managed_increment_body(void) {
    (void)atomic_fetch_add_explicit(&atomic_managed_counter, 1, memory_order_seq_cst);
}

static uint64_t atomic_managed_counter_body(void) {
    return atomic_load_explicit(&atomic_managed_counter, memory_order_seq_cst);
}

static void atomic_managed_overflow_body(void) {
    atomic_managed_pointer = (struct atomic_managed_cells*)(uintptr_t)atomic_managed_result.overflow_address;
    atomic_managed_rmw_body();
    atomic_managed_result.overflow_failures = atomic_managed_result.rmw_failures;
}
#endif

// This entry remains verifier-native. Both increments must be one genuine
// 32/64-bit BPF atomic operation; several CPUs invoke it simultaneously.
SEC("syscall")
int atomic_runtime_increment(void) {
    (void)__atomic_fetch_add(&atomic_runtime_values.word, 1u, __ATOMIC_RELAXED);
    (void)__atomic_fetch_add(&atomic_runtime_values.doubleword, 1ull, __ATOMIC_RELAXED);
    return 0;
}

SEC("syscall")
int atomic_managed_writer(void) {
    struct capsule_result result = capsule_call_void(atomic_managed_writer_body);
    atomic_managed_result.writer_status = result.status;
    atomic_managed_result.writer_code = result.code;
    return 0;
}

SEC("syscall")
int atomic_managed_reader(void) {
    struct capsule_result result = capsule_call_void(atomic_managed_reader_body);
    atomic_managed_result.reader_status = result.status;
    atomic_managed_result.reader_code = result.code;
    return 0;
}

#if BPF_CAPSULE_TEST_MANAGED_RMW
SEC("syscall")
int atomic_managed_rmw(void) {
    struct capsule_result result = capsule_call_void(atomic_managed_rmw_body);
    atomic_managed_result.rmw_status = result.status;
    atomic_managed_result.rmw_code = result.code;
    return 0;
}

SEC("syscall")
int atomic_managed_increment(void) {
    struct capsule_result result = capsule_call_void(atomic_managed_increment_body);
    return result.status == CAPSULE_OK ? 0 : -1;
}

SEC("syscall")
int atomic_managed_counter_read(void) {
    uint64_t value = 0;
    struct capsule_result result = capsule_call(&value, atomic_managed_counter_body);
    atomic_managed_result.counter_status = result.status;
    atomic_managed_result.counter_code = result.code;
    atomic_managed_result.counter_value = value;
    return 0;
}

SEC("syscall")
int atomic_managed_overflow(void) {
    struct capsule_result result = capsule_call_void(atomic_managed_overflow_body);
    atomic_managed_result.overflow_status = result.status;
    atomic_managed_result.overflow_code = result.code;
    return 0;
}
#endif

char _license[] SEC("license") = "GPL";
