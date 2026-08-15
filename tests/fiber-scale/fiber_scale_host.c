// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#include <bpf/libbpf.h>
#include <errno.h>
#include <stdio.h>

#include "bpf_capsule_host.h"

#include "../support/capsule_test.h"
#include "fiber_scale.h"

static uint64_t expected_checksum(void) {
    uint64_t checksum = 0;
    for (unsigned int i = 0; i < FIBER_SCALE_LOCAL_BYTES; ++i) {
        unsigned char value = (unsigned char)((FIBER_SCALE_SEED + i) ^ FIBER_SCALE_LAST);
        checksum += (uint64_t)value * (i + 1);
    }
    return checksum;
}

static int run(struct bpf_object* object, const char* name) {
    struct bpf_program* program = bpf_object__find_program_by_name(object, name);
    struct bpf_test_run_opts options = {.sz = sizeof(options)};
    return program ? capsule_test_run(bpf_program__fd(program), &options) : -1;
}

static int run_pool_phase(struct bpf_object* object, const char* name) {
    for (unsigned int invocation = 0; invocation <= FIBER_SCALE_COUNT; ++invocation) {
        if (run(object, name)) {
            return -1;
        }
    }
    return 0;
}

static int unified_stack_tail_matches(struct bpf_object* object, unsigned int fiber_count) {
    if (bpf_object__find_map_by_name(object, "bpf_capsule_stack_backing")) {
        return 0;
    }
    struct bpf_map* overflow = bpf_object__find_map_by_name(object, "bpf_heap_array");
    if (!overflow) {
        return bpf_object__find_map_by_name(object, "arena") != NULL;
    }
    struct bpf_map* config_map = bpf_object__find_map_by_name(object, ".rodata.bpfconfig");
    size_t config_size = 0;
    const struct __bpf_capsule_object_config* config = config_map ? bpf_map__initial_value(config_map, &config_size) : NULL;
    if (!config || config_size < sizeof(*config) || !config->stack_bytes_per_fiber || config->fiber_count != fiber_count) {
        return 0;
    }
    unsigned int selected_regions = (unsigned int)((config->memory_end + BPF_CAPSULE_MEMORY_REGION_SIZE - 1u) >> BPF_CAPSULE_MEMORY_REGION_SHIFT);
    unsigned int direct_regions = 0;
    while (__bpf_capsule_memory_region(object, direct_regions)) {
        ++direct_regions;
    }
    unsigned int expected = selected_regions - direct_regions;
    return expected && bpf_map__max_entries(overflow) == expected;
}

static int verify_preload_configuration(const char* path) {
    struct bpf_object* object = bpf_object__open_file(path, NULL);
    if (!object) {
        return -1;
    }
    const struct bpf_capsule_config zero_fibers = {
        .fiber_count = 0,
        .heap_bytes = 4ull << 20,
    };
    const struct bpf_capsule_config too_many_fibers = {
        .fiber_count = FIBER_SCALE_COUNT + 1,
        .heap_bytes = 4ull << 20,
    };
    const struct bpf_capsule_config single_fiber = {
        .fiber_count = 1,
        .heap_bytes = 4ull << 20,
    };
    errno = 0;
    int valid_errors = bpf_capsule_configure(object, zero_fibers) == -1 && errno == EINVAL;
    errno = 0;
    valid_errors = valid_errors && bpf_capsule_configure(object, too_many_fibers) == -1 && errno == E2BIG;
    if (!valid_errors || bpf_capsule_configure(object, single_fiber)) {
        bpf_object__close(object);
        return -1;
    }
    if (!unified_stack_tail_matches(object, 1) || capsule_test_load_object(object) || bpf_capsule_finish_initialization(object)) {
        bpf_object__close(object);
        return -1;
    }

    size_t size = 0;
    struct bpf_map* result_map = bpf_object__find_map_by_name(object, ".data.fscale");
    volatile struct fiber_scale_result* result = result_map ? bpf_map__initial_value(result_map, &size) : NULL;
    int error = !result || size < sizeof(*result) || run(object, "fiber_scale_count") || run(object, "fiber_scale_pool_acquire") ||
        run(object, "fiber_scale_pool_acquire");
    int pass = !error && result->call_status == CAPSULE_OK && result->active_fibers == 1 && result->acquire_attempts == 2 && result->acquired == 1 &&
        result->acquire_failures == 1;
    bpf_object__close(object);
    return pass ? 0 : -1;
}

int main(int argc, char** argv) {
    if (argc != 2) {
        fprintf(stderr, "usage: fiber_scale_host OBJECT\n");
        return 2;
    }

    if (verify_preload_configuration(argv[1])) {
        fprintf(stderr, "pre-load fiber configuration failed\n");
        return 1;
    }

    struct bpf_object* object = bpf_object__open_file(argv[1], NULL);
    const struct bpf_capsule_config config = {
        .fiber_count = FIBER_SCALE_COUNT,
        .heap_bytes = 4ull << 20,
    };
    if (!object || bpf_capsule_configure(object, config) || !unified_stack_tail_matches(object, FIBER_SCALE_COUNT) || capsule_test_load_object(object) ||
        bpf_capsule_finish_initialization(object)) {
        fprintf(stderr, "cannot load 512-fiber scale object\n");
        bpf_object__close(object);
        return 1;
    }

    size_t size = 0;
    struct bpf_map* map = bpf_object__find_map_by_name(object, ".data.fscale");
    volatile struct fiber_scale_result* result = map ? bpf_map__initial_value(map, &size) : NULL;
    // Linux 5.15 expands a 512-iteration native wrapper until the verifier
    // complexity budget is exhausted. Keep every lease live, but put one
    // acquisition or release in each test-run invocation so the verified
    // entry remains constant size. This tests the same pool capacity and
    // high-fiber memory path without making scheduler/verifier budget part of
    // the result.
    int error = !result || size < sizeof(*result) || run_pool_phase(object, "fiber_scale_pool_acquire") || run_pool_phase(object, "fiber_scale_pool_release") ||
        run(object, "fiber_scale_count") || run(object, "fiber_scale_high");
    uint64_t expected_sum = (uint64_t)FIBER_SCALE_LAST * FIBER_SCALE_COUNT / 2;
    int pass = !error && result->acquire_attempts == FIBER_SCALE_COUNT + 1 && result->acquired == FIBER_SCALE_COUNT && !result->acquire_failures &&
        result->acquired_sum == expected_sum && result->exhausted && result->release_attempts == FIBER_SCALE_COUNT + 1 && !result->release_failures &&
        result->recycled && result->call_status == CAPSULE_OK && result->active_fibers == FIBER_SCALE_COUNT && result->observed_fiber == FIBER_SCALE_LAST &&
        result->stack_cursor_zero && result->checksum == expected_checksum();

    printf(pass ? "FIBER-SCALE-PASS\n" : "FIBER-SCALE-FAIL\n");
    if (!pass && result) {
        fprintf(
            stderr,
            "acquire-attempts=%u acquired=%u acquire-failures=%u sum=%llu exhausted=%u release-attempts=%u release-failures=%u recycled=%u "
            "status=%u fiber=%u active=%u cursor-zero=%u checksum=%llu\n",
            result->acquire_attempts, result->acquired, result->acquire_failures, result->acquired_sum, result->exhausted, result->release_attempts,
            result->release_failures, result->recycled, result->call_status, result->observed_fiber, result->active_fibers, result->stack_cursor_zero,
            result->checksum
        );
    }
    bpf_object__close(object);
    return pass ? 0 : 1;
}
