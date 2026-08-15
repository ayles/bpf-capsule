// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#include "bpf_capsule.h"
#include "memory_test.h"

volatile struct memory_test_result memory_test_output SEC(".data.memtest");

static void memory_prepare_body(void) {
    memory_test_output.address = (uint64_t)(unsigned long)capsule_heap_start();
    memory_test_output.capacity = capsule_heap_size();
}

SEC("syscall")
int memory_prepare(void) {
    memory_test_output.capsule = capsule_call_void(memory_prepare_body);
    return 0;
}

static void memory_verify_body(void) {
    uint64_t checksum = 0xcbf29ce484222325ull;
    uint64_t offset = memory_test_output.probe_offset;
    struct __attribute__((packed)) memory_unaligned_word {
        uint64_t value;
    };
    unsigned char* heap = capsule_heap_start();
    volatile struct memory_unaligned_word* word = (void*)(heap + offset + 1);
    // Preserve an unaligned word in place. Besides checking behavior, this
    // retains the dynamic u64 load/store accessors whose emitted instruction
    // width is enforced by verify-width.cmake.
    uint64_t preserved = word->value;
    word->value = preserved;
    for (unsigned int index = 0; index < MEMORY_TEST_PROBE_BYTES; ++index) {
        checksum = (checksum ^ heap[offset + index]) * 0x100000001b3ull;
    }
    memory_test_output.checksum = checksum;
}

SEC("syscall")
int memory_verify(void) {
    memory_test_output.capsule = capsule_call_void(memory_verify_body);
    return 0;
}

char _license[] SEC("license") = "GPL";
