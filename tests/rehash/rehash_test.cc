// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
// SSA snapshots of mutable memory must survive managed calls (Lua's
// string-table resize bug), and demoting loop-carried PHIs must tolerate a
// second queued demotion becoming use-empty (Lua's searchpath bug).
#include "capsule_gtest.h"

#include "bpf_capsule_host.h"
#include "rehash_test.h"
#include "rehash.skel.h"

TEST(Rehash, SnapshotSurvivesManagedCall) {
    CAPSULE_REQUIRE_BPF_PRIVILEGE();
    struct rehash* skeleton = rehash__open();
    ASSERT_NE(skeleton, nullptr);
    struct bpf_capsule capsule = {};
    struct bpf_capsule_config capsule_configuration = {};
    capsule_configuration.fiber_count = 1;
    capsule_configuration.heap_bytes = 4ull << 20;
    ASSERT_EQ(bpf_capsule_configure(&capsule, skeleton->obj, capsule_configuration), 0) << strerror(errno);
    ASSERT_EQ(rehash__load(skeleton), 0) << strerror(errno);
    ASSERT_EQ(bpf_capsule_initialize(&capsule), 0) << strerror(errno);

    volatile struct rehash_test_result* result = &skeleton->data_rehash->rehash_output;
    ASSERT_EQ(capsule_test_run_program(skeleton->obj, "rehash_test_run"), 0) << strerror(errno);
    unsigned int drains = 0;
    while (result->capsule.status == CAPSULE_PENDING && drains++ < 1024) {
        ASSERT_EQ(capsule_test_run_program(skeleton->obj, "rehash_test_continue"), 0) << strerror(errno);
    }

    EXPECT_EQ(result->capsule.status, (unsigned)CAPSULE_OK);
    EXPECT_EQ(result->capsule.code, 0);
    EXPECT_EQ(result->failures, 0u);
    EXPECT_EQ(result->old_size, 1u);
    EXPECT_EQ(result->new_size, 2u);
    EXPECT_EQ(result->calls, 2u);
    EXPECT_EQ(result->grew, 2u);
    EXPECT_EQ(result->poison_calls, 2u);

    EXPECT_EQ(bpf_capsule_release(&capsule), 0) << strerror(errno);
    rehash__destroy(skeleton);
}
