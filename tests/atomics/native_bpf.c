// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#include "bpf_capsule.h"

#include "native.h"

volatile struct atomic_runtime_values atomic_runtime_values SEC(".data.atomrun") = {
    .word = ATOMIC_RUNTIME_INITIAL_WORD,
    .doubleword = ATOMIC_RUNTIME_INITIAL_DOUBLEWORD,
};

struct atomic_managed_cells {
    unsigned char byte;
    unsigned char byte_padding;
    unsigned short half;
    unsigned int word;
    uint64_t doubleword;
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
        __atomic_store_n(&cells->byte, alternate ? ATOMIC_MANAGED_BYTE_B : ATOMIC_MANAGED_BYTE_A, __ATOMIC_RELAXED);
        __atomic_store_n(&cells->half, alternate ? ATOMIC_MANAGED_HALF_B : ATOMIC_MANAGED_HALF_A, __ATOMIC_RELAXED);
        __atomic_store_n(&cells->word, alternate ? ATOMIC_MANAGED_WORD_B : ATOMIC_MANAGED_WORD_A, __ATOMIC_RELAXED);
        __atomic_store_n(&cells->doubleword, alternate ? ATOMIC_MANAGED_DOUBLEWORD_B : ATOMIC_MANAGED_DOUBLEWORD_A, __ATOMIC_RELAXED);
    }
    atomic_managed_result.writer_failures = 0;
}

static void atomic_managed_reader_body(void) {
    struct atomic_managed_cells* cells = atomic_managed_pointer;
    uint64_t failures = 0;
    for (unsigned int iteration = 0; iteration < ATOMIC_MANAGED_ITERATIONS; ++iteration) {
        unsigned char byte = __atomic_load_n(&cells->byte, __ATOMIC_RELAXED);
        unsigned short half = __atomic_load_n(&cells->half, __ATOMIC_RELAXED);
        unsigned int word = __atomic_load_n(&cells->word, __ATOMIC_RELAXED);
        uint64_t doubleword = __atomic_load_n(&cells->doubleword, __ATOMIC_RELAXED);
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

char _license[] SEC("license") = "GPL";
