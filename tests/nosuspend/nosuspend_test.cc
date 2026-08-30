// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
// The native_contract chain must run natively (never
// suspend), and flattening it must retire the now-unreachable original API.
#include "capsule_gtest.h"

#include "bpf_capsule_host.h"
#include "nosuspend_test.h"
#include "nosuspend.skel.h"

TEST(NoSuspend, ContractRunsNatively) {
    CAPSULE_REQUIRE_BPF_PRIVILEGE();
    struct nosuspend* skeleton = nosuspend__open();
    ASSERT_NE(skeleton, nullptr);
    struct bpf_capsule capsule = {};
    struct bpf_capsule_config capsule_configuration = {};
    capsule_configuration.fiber_count = 1;
    capsule_configuration.heap_bytes = 4ull << 20;
    ASSERT_EQ(bpf_capsule_configure(&capsule, skeleton->obj, capsule_configuration), 0) << strerror(errno);
    ASSERT_EQ(nosuspend__load(skeleton), 0) << strerror(errno);
    ASSERT_EQ(bpf_capsule_initialize(&capsule), 0) << strerror(errno);

    volatile struct nosuspend_result* result = &skeleton->data_nsresult->nosuspend_output;
    ASSERT_EQ(capsule_test_run_program(skeleton->obj, "native_contract_run"), 0) << strerror(errno);

    uint64_t expected = ((7ull * 17 + 3) ^ 0x5a5a) + 11;
    EXPECT_EQ(result->status, (unsigned)CAPSULE_OK);
    EXPECT_EQ(result->code, 0);
    EXPECT_EQ(result->value, expected);

    EXPECT_EQ(bpf_capsule_release(&capsule), 0) << strerror(errno);
    nosuspend__destroy(skeleton);
}
