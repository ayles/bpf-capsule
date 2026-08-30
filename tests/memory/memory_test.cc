// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
// Managed memory: pre-load heap sizing grows the selected backend, the
// host-reserved prefix is real memory the guest does not see, host memory I/O
// round-trips beyond the fixed direct-map budget and across a backend
// boundary, invalid addresses are rejected, and the guest observes the same
// bytes.
#include "capsule_gtest.h"

#include "bpf_capsule_host.h"
#include "bpf_capsule_names.h"
#include "memory_test.h"
#include "memory.skel.h"

namespace {

unsigned int backing_entries(struct bpf_object* object) {
    struct bpf_map* map = bpf_object__find_map_by_name(object, BPF_CAPSULE_MAP_HEAP_ARRAY);
    if (!map) {
        map = bpf_object__find_map_by_name(object, BPF_CAPSULE_MAP_ARENA);
    }
    return map ? bpf_map__max_entries(map) : 0;
}

TEST(Memory, HeapSizingReservedPrefixAndHostIo) {
    CAPSULE_REQUIRE_BPF_PRIVILEGE();
    struct memory* skeleton = memory__open();
    ASSERT_NE(skeleton, nullptr);
    struct bpf_capsule capsule = {};
    struct bpf_object* object = skeleton->obj;

    // Growing heap requests must grow the backing map monotonically.
    struct bpf_capsule_config zero_heap = {};
    zero_heap.fiber_count = 1;
    struct bpf_capsule_config small_heap = {};
    small_heap.fiber_count = 1;
    small_heap.heap_bytes = 1ull << 20;
    struct bpf_capsule_config large_heap = {};
    large_heap.fiber_count = 1;
    large_heap.heap_bytes = MEMORY_TEST_BYTES;
    large_heap.reserved_bytes = MEMORY_TEST_PROBE_BYTES;

    ASSERT_EQ(bpf_capsule_configure(&capsule, object, zero_heap), 0) << strerror(errno);
    unsigned int zero_entries = backing_entries(object);
    ASSERT_EQ(bpf_capsule_configure(&capsule, object, small_heap), 0) << strerror(errno);
    unsigned int small_entries = backing_entries(object);
    ASSERT_EQ(bpf_capsule_configure(&capsule, object, large_heap), 0) << strerror(errno);
    unsigned int large_entries = backing_entries(object);
    EXPECT_NE(zero_entries, 0u);
    EXPECT_GE(small_entries, zero_entries);
    EXPECT_GT(large_entries, small_entries);

    ASSERT_EQ(memory__load(skeleton), 0) << strerror(errno);
    ASSERT_EQ(bpf_capsule_initialize(&capsule), 0) << strerror(errno);

    // The host-reserved prefix opens the heap: probe it through the memory
    // view, then require the guest to see exactly the remaining suffix.
    unsigned char* bootstrap_address = static_cast<unsigned char*>(bpf_capsule_memory_reserved_start(&capsule));
    uint64_t bootstrap_reserved = bpf_capsule_memory_reserved_size(&capsule);
    ASSERT_EQ(bootstrap_reserved, (uint64_t)MEMORY_TEST_PROBE_BYTES);
    unsigned char bootstrap_expected[MEMORY_TEST_PROBE_BYTES];
    unsigned char bootstrap_observed[MEMORY_TEST_PROBE_BYTES] = {0};
    for (unsigned int index = 0; index < sizeof(bootstrap_expected); ++index) {
        bootstrap_expected[index] = (unsigned char)(index * 19u + 7u);
    }
    ASSERT_EQ(bpf_capsule_memcpy(&capsule, bootstrap_address, bootstrap_expected, sizeof(bootstrap_expected)), 0);
    ASSERT_EQ(bpf_capsule_memcpy(&capsule, bootstrap_observed, bootstrap_address, sizeof(bootstrap_observed)), 0);
    EXPECT_EQ(memcmp(bootstrap_expected, bootstrap_observed, sizeof(bootstrap_expected)), 0);

    size_t result_size = 0;
    volatile struct memory_test_result* result = (volatile struct memory_test_result*)capsule_test_global(object, "memory_test_output", &result_size);
    ASSERT_NE(result, nullptr);
    ASSERT_GE(result_size, sizeof(*result));

    ASSERT_EQ(capsule_test_run_program(object, "memory_prepare"), 0) << strerror(errno);
    ASSERT_EQ(result->capsule.status, (unsigned)CAPSULE_OK);
    EXPECT_EQ(result->capacity, MEMORY_TEST_BYTES - bootstrap_reserved);
    EXPECT_EQ(result->address, bootstrap_address + bootstrap_reserved);
    // The guest-observed pointer carries the same upper half the host sees.
    // Both backends expose the same full pointer representation.
    EXPECT_EQ(result->pointer_high, (uint32_t)((uintptr_t)bpf_capsule_memory_start(&capsule) >> 32));

    // Probe beyond the complete fixed direct-map budget, then straddle the
    // next fixed-region boundary. The arena backend executes the same flat
    // memory operation.
    unsigned char expected[MEMORY_TEST_PROBE_BYTES];
    unsigned char observed[MEMORY_TEST_PROBE_BYTES] = {0};
    for (unsigned int index = 0; index < sizeof(expected); ++index) {
        expected[index] = (unsigned char)(index * 37u + 11u);
    }
    uint64_t probe_base = (uint64_t)MEMORY_TEST_DIRECT_REGIONS * MEMORY_TEST_REGION_SIZE;
    unsigned char* probe_address = result->address + probe_base;
    uint64_t distance = MEMORY_TEST_REGION_SIZE - ((uintptr_t)probe_address & (MEMORY_TEST_REGION_SIZE - 1u));
    uint64_t prefix = distance < MEMORY_TEST_PROBE_BYTES / 4u ? distance : MEMORY_TEST_PROBE_BYTES / 4u;
    uint64_t offset = probe_base + distance - prefix;
    result->probe_offset = offset;
    unsigned char* address = result->address + offset;

    ASSERT_LE(offset + sizeof(expected), result->capacity);
    ASSERT_EQ(bpf_capsule_memcpy(&capsule, address, expected, sizeof(expected)), 0) << strerror(errno);
    ASSERT_EQ(bpf_capsule_memcpy(&capsule, observed, address, sizeof(observed)), 0) << strerror(errno);
    EXPECT_EQ(memcmp(expected, observed, sizeof(expected)), 0);

    // With both pointers in the window, memcpy selects the write path and
    // validates both Capsule ranges.
    unsigned char capsule_observed[MEMORY_TEST_PROBE_BYTES] = {0};
    unsigned char* capsule_copy = address + sizeof(expected);
    ASSERT_LE(offset + 2 * sizeof(expected), result->capacity);
    ASSERT_EQ(bpf_capsule_memcpy(&capsule, capsule_copy, address, sizeof(expected)), 0) << strerror(errno);
    ASSERT_EQ(bpf_capsule_memcpy(&capsule, capsule_observed, capsule_copy, sizeof(capsule_observed)), 0) << strerror(errno);
    EXPECT_EQ(memcmp(expected, capsule_observed, sizeof(expected)), 0);

    // Argument validation.
    errno = 0;
    EXPECT_EQ(bpf_capsule_memcpy(&capsule, address, nullptr, 1), -1);
    EXPECT_EQ(errno, EINVAL);
    errno = 0;
    EXPECT_EQ(bpf_capsule_memcpy(&capsule, nullptr, address, 1), -1);
    EXPECT_EQ(errno, EINVAL);
    EXPECT_EQ(bpf_capsule_memcpy(nullptr, address, expected, 1), -1);
    EXPECT_EQ(errno, EINVAL);
    EXPECT_EQ(bpf_capsule_memcpy(nullptr, observed, address, 1), -1);
    EXPECT_EQ(errno, EINVAL);
    errno = 0;
    EXPECT_EQ(bpf_capsule_memcpy(&capsule, observed, expected, 1), -1);
    EXPECT_EQ(errno, EFAULT) << "one side of the copy must belong to the Capsule";

    // An address whose upper half does not match the object's window must
    // fault rather than alias a valid low word: on the arena tier pointers
    // are full user virtual addresses checked at full width. Flipping a
    // high bit leaves the low word intact but exits the window on every
    // backend and every placement.
    errno = 0;
    EXPECT_EQ(bpf_capsule_memcpy(&capsule, (void*)((uintptr_t)address ^ (1ull << 40)), expected, 1), -1);
    EXPECT_EQ(errno, EFAULT);
    errno = 0;
    EXPECT_EQ(bpf_capsule_memcpy(&capsule, observed, (const void*)((uintptr_t)address ^ (1ull << 40)), 1), -1);
    EXPECT_EQ(errno, EFAULT);

    // Out-of-bounds addresses derived from the object's own configuration.
    struct bpf_map* config_map = bpf_object__find_map_by_name(object, BPF_CAPSULE_SECTION_CONFIG);
    size_t config_size = 0;
    const struct __bpf_capsule_object_config* config =
        config_map ? (const struct __bpf_capsule_object_config*)bpf_map__initial_value(config_map, &config_size) : nullptr;
    ASSERT_NE(config, nullptr);
    ASSERT_GE(config_size, sizeof(*config));
    uintptr_t virtual_base = (uintptr_t)result->address - config->heap_base;
    errno = 0;
    EXPECT_EQ(bpf_capsule_memcpy(&capsule, (void*)virtual_base, expected, 1), -1);
    EXPECT_EQ(errno, EFAULT) << "the null page is not Capsule memory";
    errno = 0;
    EXPECT_EQ(bpf_capsule_memcpy(&capsule, observed, (const void*)virtual_base, 1), -1);
    EXPECT_EQ(errno, EFAULT) << "the null page is not Capsule memory";
    errno = 0;
    EXPECT_EQ(bpf_capsule_memcpy(&capsule, (void*)(virtual_base + config->memory_end), expected, 1), -1);
    EXPECT_EQ(errno, EFAULT);
    errno = 0;
    EXPECT_EQ(bpf_capsule_memcpy(&capsule, observed, (const void*)(virtual_base + config->memory_end), 1), -1);
    EXPECT_EQ(errno, EFAULT);
    if (config->stack_base > config->heap_base + config->heap_bytes) {
        errno = 0;
        EXPECT_EQ(bpf_capsule_memcpy(&capsule, (void*)(virtual_base + config->heap_base + config->heap_bytes), expected, 1), -1);
        EXPECT_EQ(errno, EFAULT);
    }

    // The guest must observe exactly the bytes the host staged.
    uint64_t checksum = 0xcbf29ce484222325ull;
    for (unsigned int index = 0; index < sizeof(expected); ++index) {
        checksum = (checksum ^ expected[index]) * 0x100000001b3ull;
    }
    ASSERT_EQ(capsule_test_run_program(object, "memory_verify"), 0) << strerror(errno);
    EXPECT_EQ(result->capsule.status, (unsigned)CAPSULE_OK);
    EXPECT_EQ(result->checksum, checksum);

    EXPECT_EQ(bpf_capsule_release(&capsule), 0) << strerror(errno);
    EXPECT_EQ(bpf_capsule_release(&capsule), 0) << "release must be idempotent";
    memory__destroy(skeleton);
}

// The prepared view makes capsule pointers host-dereferenceable for
// reading on every tier: the host reserves a 4 GiB-aligned span before
// load, the base is baked into the frozen config, and guest pointers are
// base + object offset program-wide. Reads go straight through the mapping
// (including across a region boundary, where the contiguous view holds the
// real next-region bytes rather than the shadow suffix); writes stay in
// the helper, which accepts the same based addresses.
TEST(Memory, DirectViewSharedPointers) {
    CAPSULE_REQUIRE_BPF_PRIVILEGE();
    struct memory* skeleton = memory__open();
    ASSERT_NE(skeleton, nullptr);
    struct bpf_capsule capsule = {};
    struct bpf_object* object = skeleton->obj;

    struct bpf_capsule_config wanted = {};
    wanted.fiber_count = 1;
    wanted.heap_bytes = MEMORY_TEST_BYTES;
    ASSERT_EQ(bpf_capsule_configure(&capsule, object, wanted), 0) << strerror(errno);
    ASSERT_EQ(memory__load(skeleton), 0) << strerror(errno);
    ASSERT_EQ(bpf_capsule_initialize(&capsule), 0) << strerror(errno);

    const void* start = bpf_capsule_memory_start(&capsule);
    ASSERT_NE(start, nullptr);
    uintptr_t start_address = (uintptr_t)start;
    struct bpf_map* config_map = bpf_object__find_map_by_name(object, BPF_CAPSULE_SECTION_CONFIG);
    size_t config_size = 0;
    const struct __bpf_capsule_object_config* config =
        config_map ? (const struct __bpf_capsule_object_config*)bpf_map__initial_value(config_map, &config_size) : nullptr;
    ASSERT_NE(config, nullptr);
    ASSERT_GE(config_size, sizeof(*config));
    if (config->memory_backend == BPF_CAPSULE_MEMORY_FIXED) {
        // The fixed tier's alignment contract: base | offset == base +
        // offset, so the backend recovers object offsets by truncation.
        EXPECT_EQ(start_address & 0xffffffffu, 0u);
    }

    size_t result_size = 0;
    volatile struct memory_test_result* result = (volatile struct memory_test_result*)capsule_test_global(object, "memory_test_output", &result_size);
    ASSERT_NE(result, nullptr);
    ASSERT_EQ(capsule_test_run_program(object, "memory_prepare"), 0) << strerror(errno);
    ASSERT_EQ(result->capsule.status, (unsigned)CAPSULE_OK);

    // The guest-published heap pointer is a host pointer now.
    EXPECT_EQ(result->pointer_high, (uint32_t)(start_address >> 32));

    // Walk the guest-built chain by dereferencing the pointers it stored in
    // its own structs: 0 -> 2 -> 1 -> 3 by construction, so a correct walk
    // proves the host read stored pointer values, not layout.
    const struct memory_test_node* node = result->chain;
    uint64_t walked[MEMORY_TEST_NODE_COUNT] = {0};
    unsigned int count = 0;
    while (node && count < MEMORY_TEST_NODE_COUNT) {
        walked[count++] = node->value;
        node = node->next;
    }
    EXPECT_EQ(node, nullptr);
    ASSERT_EQ(count, MEMORY_TEST_NODE_COUNT);
    EXPECT_EQ(walked[0], 0x1000u);
    EXPECT_EQ(walked[1], 0x1002u);
    EXPECT_EQ(walked[2], 0x1001u);
    EXPECT_EQ(walked[3], 0x1003u);

    // Stage a pattern across a region boundary through the helper, then
    // read it back by plain dereference of the published pointer.
    unsigned char expected[MEMORY_TEST_PROBE_BYTES];
    for (unsigned int index = 0; index < sizeof(expected); ++index) {
        expected[index] = (unsigned char)(index * 73u + 29u);
    }
    uint64_t boundary = MEMORY_TEST_REGION_SIZE - ((uintptr_t)result->address & (MEMORY_TEST_REGION_SIZE - 1u));
    uint64_t offset = boundary > MEMORY_TEST_PROBE_BYTES / 2u ? boundary - MEMORY_TEST_PROBE_BYTES / 2u : 0;
    ASSERT_LE(offset + sizeof(expected), result->capacity);
    unsigned char* address = result->address + offset;
    ASSERT_EQ(bpf_capsule_memcpy(&capsule, address, expected, sizeof(expected)), 0) << strerror(errno);
    EXPECT_EQ(memcmp(address, expected, sizeof(expected)), 0);

    EXPECT_EQ(bpf_capsule_release(&capsule), 0) << strerror(errno);
    EXPECT_EQ(bpf_capsule_release(&capsule), 0) << "release must be idempotent";
    memory__destroy(skeleton);
}

} // namespace
