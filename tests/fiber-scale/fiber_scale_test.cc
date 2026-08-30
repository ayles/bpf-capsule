// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
// Fiber pool at full scale: pre-load configuration validation (EINVAL/E2BIG),
// backend sizing, 512-lease pool exhaustion and recycling, and a high fiber
// whose stack begins beyond the fixed backend's direct-map prefix.
#include "capsule_gtest.h"

#include "bpf_capsule_host.h"
#include "bpf_capsule_abi.h"
#include "bpf_capsule_names.h"
#include "fiber_scale.h"
#include "fiber_scale.skel.h"

namespace {

uint64_t expected_checksum() {
    uint64_t checksum = 0;
    for (unsigned int i = 0; i < FIBER_SCALE_LOCAL_BYTES; ++i) {
        unsigned char value = (unsigned char)((FIBER_SCALE_SEED + i) ^ FIBER_SCALE_LAST);
        checksum += (uint64_t)value * (i + 1);
    }
    return checksum;
}

void run_pool_phase(struct bpf_object* object, const char* name) {
    for (unsigned int invocation = 0; invocation <= FIBER_SCALE_COUNT; ++invocation) {
        ASSERT_EQ(capsule_test_run_program(object, name), 0) << name << " invocation " << invocation << ": " << strerror(errno);
    }
}

void expect_backend_layout(struct bpf_object* object, unsigned int fiber_count) {
    ASSERT_EQ(bpf_object__find_map_by_name(object, "bpf_capsule_stack_backing"), nullptr);
    struct bpf_map* config_map = bpf_object__find_map_by_name(object, BPF_CAPSULE_SECTION_CONFIG);
    size_t config_size = 0;
    const struct __bpf_capsule_object_config* config =
        config_map ? (const struct __bpf_capsule_object_config*)bpf_map__initial_value(config_map, &config_size) : nullptr;
    ASSERT_NE(config, nullptr);
    ASSERT_GE(config_size, sizeof(*config));
    ASSERT_NE(config->stack_bytes_per_fiber, 0u);
    ASSERT_EQ(config->fiber_count, fiber_count);
    struct bpf_map* arena = bpf_object__find_map_by_name(object, BPF_CAPSULE_MAP_ARENA);
    struct bpf_map* overflow = bpf_object__find_map_by_name(object, BPF_CAPSULE_MAP_HEAP_ARRAY);
    if (config->memory_backend == BPF_CAPSULE_MEMORY_ARENA) {
        ASSERT_NE(arena, nullptr);
        ASSERT_EQ(overflow, nullptr);
        unsigned int selected_pages = (config->memory_end + BPF_CAPSULE_ARENA_PAGE_SIZE - 1u) >> BPF_CAPSULE_ARENA_PAGE_SHIFT;
        EXPECT_EQ(bpf_map__max_entries(arena), config->arena_image_pages + selected_pages + BPF_CAPSULE_ARENA_SLICE_SLACK_PAGES(config->stack_bytes_per_fiber));
        return;
    }
    ASSERT_EQ(config->memory_backend, (unsigned)BPF_CAPSULE_MEMORY_FIXED);
    ASSERT_EQ(arena, nullptr);
    ASSERT_NE(overflow, nullptr);
    unsigned int selected_regions = (config->memory_end + BPF_CAPSULE_MEMORY_REGION_SIZE - 1u) >> BPF_CAPSULE_MEMORY_REGION_SHIFT;
    unsigned int direct_regions = 0;
    for (;; ++direct_regions) {
        char data_name[32];
        char bss_name[32];
        snprintf(data_name, sizeof(data_name), BPF_CAPSULE_SECTION_DATA_HEAP_PREFIX "%u", direct_regions);
        snprintf(bss_name, sizeof(bss_name), BPF_CAPSULE_SECTION_BSS_HEAP_PREFIX "%u", direct_regions);
        if (!bpf_object__find_map_by_name(object, data_name) && !bpf_object__find_map_by_name(object, bss_name)) {
            break;
        }
    }
    ASSERT_GT(selected_regions, direct_regions);
    EXPECT_EQ(bpf_map__max_entries(overflow), selected_regions - direct_regions);
}

TEST(FiberScale, PreloadConfigurationValidation) {
    CAPSULE_REQUIRE_BPF_PRIVILEGE();
    struct fiber_scale* skeleton = fiber_scale__open();
    ASSERT_NE(skeleton, nullptr);
    struct bpf_capsule capsule = {};
    struct bpf_object* object = skeleton->obj;

    struct bpf_capsule_config zero_fibers = {};
    zero_fibers.heap_bytes = 4ull << 20;
    struct bpf_capsule_config too_many_fibers = {};
    too_many_fibers.fiber_count = FIBER_SCALE_COUNT + 1;
    too_many_fibers.heap_bytes = 4ull << 20;
    struct bpf_capsule_config single_fiber = {};
    single_fiber.fiber_count = 1;
    single_fiber.heap_bytes = 4ull << 20;

    errno = 0;
    EXPECT_EQ(bpf_capsule_configure(&capsule, object, zero_fibers), -1);
    EXPECT_EQ(errno, EINVAL);
    errno = 0;
    EXPECT_EQ(bpf_capsule_configure(&capsule, object, too_many_fibers), -1);
    EXPECT_EQ(errno, E2BIG);
    ASSERT_EQ(bpf_capsule_configure(&capsule, object, single_fiber), 0) << strerror(errno);
    expect_backend_layout(object, 1);
    ASSERT_EQ(fiber_scale__load(skeleton), 0) << strerror(errno);
    ASSERT_EQ(bpf_capsule_initialize(&capsule), 0) << strerror(errno);

    volatile struct fiber_scale_result* result = &skeleton->data_fscale->fiber_scale_output;
    ASSERT_EQ(capsule_test_run_program(object, "fiber_scale_count"), 0) << strerror(errno);
    // With one active fiber, one acquire succeeds and the second fails.
    ASSERT_EQ(capsule_test_run_program(object, "fiber_scale_pool_acquire"), 0) << strerror(errno);
    ASSERT_EQ(capsule_test_run_program(object, "fiber_scale_pool_acquire"), 0) << strerror(errno);
    EXPECT_EQ(result->call_status, (unsigned)CAPSULE_OK);
    EXPECT_EQ(result->active_fibers, 1u);
    EXPECT_EQ(result->acquire_attempts, 2u);
    EXPECT_EQ(result->acquired, 1u);
    EXPECT_EQ(result->acquire_failures, 1u);

    EXPECT_EQ(bpf_capsule_release(&capsule), 0) << strerror(errno);
    fiber_scale__destroy(skeleton);
}

TEST(FiberScale, FullPoolLeaseReleaseAndHighFiber) {
    CAPSULE_REQUIRE_BPF_PRIVILEGE();
    struct fiber_scale* skeleton = fiber_scale__open();
    ASSERT_NE(skeleton, nullptr);
    struct bpf_capsule capsule = {};
    struct bpf_object* object = skeleton->obj;
    struct bpf_capsule_config config = {};
    config.fiber_count = FIBER_SCALE_COUNT;
    config.heap_bytes = 4ull << 20;
    ASSERT_EQ(bpf_capsule_configure(&capsule, object, config), 0) << strerror(errno);
    expect_backend_layout(object, FIBER_SCALE_COUNT);
    ASSERT_EQ(fiber_scale__load(skeleton), 0) << strerror(errno);
    ASSERT_EQ(bpf_capsule_initialize(&capsule), 0) << strerror(errno);

    volatile struct fiber_scale_result* result = &skeleton->data_fscale->fiber_scale_output;

    // Linux 5.15 expands a 512-iteration native wrapper until the verifier
    // budget is exhausted; one acquisition or release per invocation keeps
    // the verified entry constant-size.
    run_pool_phase(object, "fiber_scale_pool_acquire");
    run_pool_phase(object, "fiber_scale_pool_release");
    ASSERT_EQ(capsule_test_run_program(object, "fiber_scale_count"), 0) << strerror(errno);
    ASSERT_EQ(capsule_test_run_program(object, "fiber_scale_high"), 0) << strerror(errno);

    uint64_t expected_sum = (uint64_t)FIBER_SCALE_LAST * FIBER_SCALE_COUNT / 2;
    EXPECT_EQ(result->acquire_attempts, FIBER_SCALE_COUNT + 1);
    EXPECT_EQ(result->acquired, FIBER_SCALE_COUNT);
    EXPECT_EQ(result->acquire_failures, 0u);
    EXPECT_EQ(result->acquired_sum, expected_sum) << "every fiber index leased exactly once";
    EXPECT_NE(result->exhausted, 0u) << "the pool reports exhaustion after the last lease";
    EXPECT_EQ(result->release_attempts, FIBER_SCALE_COUNT + 1);
    EXPECT_EQ(result->release_failures, 0u);
    EXPECT_NE(result->recycled, 0u) << "a released fiber is leasable again";
    EXPECT_EQ(result->call_status, (unsigned)CAPSULE_OK);
    EXPECT_EQ(result->active_fibers, FIBER_SCALE_COUNT);
    EXPECT_EQ(result->observed_fiber, FIBER_SCALE_LAST);
    EXPECT_NE(result->stack_cursor_zero, 0u) << "completing the call reset the high fiber to idle";
    EXPECT_EQ(result->checksum, expected_checksum());

    EXPECT_EQ(bpf_capsule_release(&capsule), 0) << strerror(errno);
    fiber_scale__destroy(skeleton);
}

} // namespace
