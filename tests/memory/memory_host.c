// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#include <bpf/libbpf.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "bpf_capsule_host.h"

#include "../support/capsule_test.h"
#include "memory_test.h"

static int run(struct bpf_program* program) {
    struct bpf_test_run_opts options = {.sz = sizeof(options)};
    return program ? capsule_test_run(bpf_program__fd(program), &options) : -1;
}

static unsigned int backing_entries(struct bpf_object* object) {
    struct bpf_map* map = bpf_object__find_map_by_name(object, "bpf_heap_array");
    if (!map) {
        map = bpf_object__find_map_by_name(object, "arena");
    }
    return map ? bpf_map__max_entries(map) : 0;
}

int main(int argc, char** argv) {
    if (argc != 2) {
        fprintf(stderr, "usage: memory_test_host OBJECT\n");
        return 2;
    }
    struct bpf_object* object = bpf_object__open_file(argv[1], NULL);
    const struct bpf_capsule_config zero_heap = {
        .fiber_count = 1,
        .heap_bytes = 0,
    };
    const struct bpf_capsule_config small_heap = {
        .fiber_count = 1,
        .heap_bytes = 1ull << 20,
    };
    const struct bpf_capsule_config large_heap = {
        .fiber_count = 1,
        .heap_bytes = MEMORY_TEST_BYTES,
        .reserved_bytes = MEMORY_TEST_PROBE_BYTES,
    };
    errno = 0;
    int configured_zero = object && !bpf_capsule_configure(object, zero_heap);
    unsigned int zero_entries = configured_zero ? backing_entries(object) : 0;
    int configured_small = object && !bpf_capsule_configure(object, small_heap);
    unsigned int small_entries = configured_small ? backing_entries(object) : 0;
    int configured_large = configured_small && !bpf_capsule_configure(object, large_heap);
    unsigned int large_entries = configured_large ? backing_entries(object) : 0;
    if (!configured_zero || !configured_large || !zero_entries || small_entries < zero_entries || large_entries <= small_entries ||
        capsule_test_load_object(object) || bpf_capsule_finish_initialization(object)) {
        fprintf(stderr, "cannot load memory I/O object\n");
        bpf_object__close(object);
        return 1;
    }

    struct bpf_capsule_memory memory;
    if (bpf_capsule_memory(object, &memory)) {
        fprintf(stderr, "cannot map Capsule memory\n");
        bpf_object__close(object);
        return 1;
    }
    // The host-reserved prefix opens the heap: probe it through the memory
    // view, then require the guest to see exactly the remaining suffix.
    uint64_t bootstrap_address = bpf_capsule_memory_reserved_start(&memory);
    uint64_t bootstrap_reserved = bpf_capsule_memory_reserved_size(&memory);
    unsigned char bootstrap_expected[MEMORY_TEST_PROBE_BYTES];
    unsigned char bootstrap_observed[MEMORY_TEST_PROBE_BYTES] = {0};
    for (unsigned int index = 0; index < sizeof(bootstrap_expected); ++index) {
        bootstrap_expected[index] = (unsigned char)(index * 19u + 7u);
    }
    int reserved = bootstrap_reserved == MEMORY_TEST_PROBE_BYTES &&
        !bpf_capsule_memory_write(&memory, bootstrap_address, bootstrap_expected, sizeof(bootstrap_expected)) &&
        !bpf_capsule_memory_read(&memory, bootstrap_observed, bootstrap_address, sizeof(bootstrap_observed)) &&
        !memcmp(bootstrap_expected, bootstrap_observed, sizeof(bootstrap_expected));

    size_t map_size = 0;
    volatile struct memory_test_result* result = capsule_test_global(object, "memory_test_output", &map_size);
    struct bpf_program* prepare = bpf_object__find_program_by_name(object, "memory_prepare");
    struct bpf_program* verify = bpf_object__find_program_by_name(object, "memory_verify");
    int pass = reserved && result && map_size >= sizeof(*result) && !run(prepare) && result->capsule.status == CAPSULE_OK &&
        result->capacity == MEMORY_TEST_BYTES - bootstrap_reserved && result->address == bootstrap_address + bootstrap_reserved;

    unsigned char expected[MEMORY_TEST_PROBE_BYTES];
    unsigned char observed[MEMORY_TEST_PROBE_BYTES] = {0};
    for (unsigned int index = 0; index < sizeof(expected); ++index) {
        expected[index] = (unsigned char)(index * 37u + 11u);
    }

    // Probe beyond the complete direct-map budget, then straddle the next
    // logical boundary. On 5.15 this is necessarily ARRAY-backed capacity;
    // on the arena tier it remains the same ordinary flat-memory operation.
    uint64_t probe_base = (uint64_t)MEMORY_TEST_DIRECT_REGIONS * MEMORY_TEST_REGION_SIZE;
    uint64_t probe_address = (result ? result->address : 0) + probe_base;
    uint64_t distance = MEMORY_TEST_REGION_SIZE - (probe_address & (MEMORY_TEST_REGION_SIZE - 1u));
    uint64_t prefix = distance < MEMORY_TEST_PROBE_BYTES / 4u ? distance : MEMORY_TEST_PROBE_BYTES / 4u;
    uint64_t offset = probe_base + distance - prefix;
    if (result) {
        result->probe_offset = offset;
    }
    uint64_t address = result ? result->address + offset : 0;

    errno = 0;
    pass = pass && offset + sizeof(expected) <= result->capacity && !bpf_capsule_memory_write(&memory, address, expected, sizeof(expected)) &&
        !bpf_capsule_memory_read(&memory, observed, address, sizeof(observed)) && !memcmp(expected, observed, sizeof(expected));

    errno = 0;
    pass = pass && bpf_capsule_memory_write(&memory, address, NULL, 1) == -1 && errno == EINVAL;
    errno = 0;
    pass = pass && bpf_capsule_memory_read(&memory, NULL, address, 1) == -1 && errno == EINVAL;
    errno = 0;
    pass = pass && bpf_capsule_memory_write(NULL, address, expected, 1) == -1 && errno == EINVAL;

    // Capsule virtual addresses are 32-bit on both backends. Rejecting high
    // aliases prevents an accidental low-word truncation from writing an
    // unrelated valid arena address.
    errno = 0;
    pass = pass && bpf_capsule_memory_write(&memory, address | (1ull << 40), expected, 1) == -1 && errno == EFAULT;

    struct bpf_map* config_map = bpf_object__find_map_by_name(object, ".rodata.bpfconfig");
    size_t config_size = 0;
    const struct __bpf_capsule_object_config* config = config_map ? bpf_map__initial_value(config_map, &config_size) : NULL;
    uint64_t virtual_base = config && result ? result->address - config->heap_base : 0;
    errno = 0;
    pass = pass && config && config_size >= sizeof(*config) && bpf_capsule_memory_write(&memory, virtual_base + config->memory_end, expected, 1) == -1 &&
        errno == EFAULT;
    if (pass && config->stack_base > config->heap_base + config->heap_bytes) {
        errno = 0;
        pass = bpf_capsule_memory_write(&memory, virtual_base + config->heap_base + config->heap_bytes, expected, 1) == -1 && errno == EFAULT;
    }

    uint64_t checksum = 0xcbf29ce484222325ull;
    for (unsigned int index = 0; index < sizeof(expected); ++index) {
        checksum = (checksum ^ expected[index]) * 0x100000001b3ull;
    }
    pass = pass && !run(verify) && result->capsule.status == CAPSULE_OK && result->checksum == checksum;

    if (!pass && result) {
        fprintf(
            stderr,
            "memory I/O status=%u code=%lld address=%llx offset=%llx "
            "capacity=%llu checksum=%llx/%llx\n",
            result->capsule.status, (long long)result->capsule.code, result->address, offset, result->capacity, result->checksum, checksum
        );
    }
    printf(pass ? "MEMORY-IO-PASS\n" : "MEMORY-IO-FAIL\n");
    bpf_object__close(object);
    return pass ? 0 : 1;
}
