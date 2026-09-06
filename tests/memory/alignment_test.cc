// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#include "capsule_gtest.h"
#include "bpf_capsule_host.h"
#include "memory_test.h"
#include "alignment.skel.h"

#include <array>
#include <algorithm>
#include <cstring>

TEST(Memory, AlignedFragmentsAndDirectHostWrites) {
    CAPSULE_REQUIRE_BPF_PRIVILEGE();
    auto* skel = alignment__open();
    ASSERT_NE(skel, nullptr);
    struct bpf_capsule capsule = {};
    const size_t span = BPF_CAPSULE_MEMORY_REGION_SIZE;
    const unsigned direct = std::max<uint64_t>(2, skel->rodata_bpfconfig->bpf_capsule_config.direct_memory_regions);
    struct bpf_capsule_config config = {};
    config.fiber_count = 1;
    config.heap_bytes = (direct + 2) * span;
    ASSERT_EQ(bpf_capsule_configure(&capsule, skel->obj, config), 0);
    EXPECT_NE(bpf_program__flags(skel->progs.alignment_run) & BPF_F_STRICT_ALIGNMENT, 0u);
    ASSERT_EQ(alignment__load(skel), 0);
    ASSERT_EQ(bpf_capsule_initialize(&capsule), 0);
    auto* base = static_cast<unsigned char*>(bpf_capsule_memory_start(&capsule));
    auto* control = &skel->data_align->alignment_control;

    // Direct/direct, direct/ARRAY, and ARRAY/ARRAY boundaries. Exercise each
    // legal alignment on either side, including every unaligned byte offset.
    for (unsigned region : {1u, direct, direct + 1}) {
        auto* boundary = base + region * span;
        for (unsigned width : {2u, 4u, 8u}) {
            for (unsigned alignment = 1; alignment <= width; alignment *= 2) {
                for (int offset = -8; offset <= 8; offset += alignment) {
                    SCOPED_TRACE(::testing::Message() << region << '/' << width << '/' << alignment << '/' << offset);
                    std::array<unsigned char, 32> expected;
                    expected.fill(0x5a);
                    memcpy(boundary - 16, expected.data(), expected.size());
                    control->address = boundary + offset;
                    control->mode = width * 8 * 16 + alignment;
                    control->value = 0xf1e2d3c4b5a69788ull;
                    uint64_t observed = 0;
                    memcpy(&observed, boundary + offset, width);
                    uint64_t value = control->value;
                    memcpy(expected.data() + 16 + offset, &value, width);
                    ASSERT_EQ(capsule_test_run_program(skel->obj, "alignment_run"), 0);
                    ASSERT_EQ(control->result.status, CAPSULE_OK);
                    EXPECT_EQ(control->observed, observed);
                    EXPECT_EQ(memcmp(boundary - 16, expected.data(), expected.size()), 0);
                }
            }
        }
#ifdef BPF_CAPSULE_TEST_MANAGED_RMW
        memset(boundary - 8, 0, 24);
        control->address = boundary - 4;
        control->mode = 0;
        control->value = 0x8877665544332211ull;
        ASSERT_EQ(capsule_test_run_program(skel->obj, "alignment_run"), 0);
        ASSERT_EQ(control->result.status, CAPSULE_OK);
        EXPECT_EQ(control->counter, 1u);
        EXPECT_EQ(*reinterpret_cast<uint32_t*>(boundary + 4), 1u);
#endif
    }
    EXPECT_EQ(bpf_capsule_release(&capsule), 0);
    alignment__destroy(skel);
}
