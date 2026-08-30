// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#include "capsule_gtest.h"

#include "bpf_capsule_host.h"
#include "csmith_case.h"
#include "csmith.skel.h"

extern "C" uint64_t csmith_native_checksum(void);

TEST(Csmith, GeneratedProgramMatchesNativeExecution) {
    CAPSULE_REQUIRE_BPF_PRIVILEGE();
    const uint64_t expected = csmith_native_checksum();
    struct csmith* skeleton = csmith__open();
    ASSERT_NE(skeleton, nullptr);
    struct bpf_capsule capsule = {};

    struct bpf_capsule_config config = {};
    config.fiber_count = 1;
    ASSERT_EQ(bpf_capsule_configure(&capsule, skeleton->obj, config), 0) << strerror(errno);
    ASSERT_EQ(csmith__load(skeleton), 0) << strerror(errno);
    ASSERT_EQ(bpf_capsule_initialize(&capsule), 0) << strerror(errno);

    volatile struct csmith_test_result* result = &skeleton->data_csmith->csmith_result;
    struct bpf_program* entry = bpf_object__find_program_by_name(skeleton->obj, "csmith_run");
    struct bpf_program* drain = bpf_object__find_program_by_name(skeleton->obj, "csmith_continue");
    ASSERT_NE(entry, nullptr);
    ASSERT_NE(drain, nullptr);
    struct bpf_test_run_opts options = {};
    options.sz = sizeof(options);
    unsigned long entries = 0;
    unsigned long drains = 0;
    ASSERT_EQ(capsule_test_drive(bpf_program__fd(entry), bpf_program__fd(drain), &options, 1024, &entries, &drains, &result->capsule), 0) << strerror(errno);
    ASSERT_EQ(result->capsule.status, (uint32_t)CAPSULE_OK);
    ASSERT_EQ(result->capsule.code, 0);
    EXPECT_EQ(result->checksum, expected) << "native checksum " << expected << ", drains " << drains;

    EXPECT_EQ(bpf_capsule_release(&capsule), 0) << strerror(errno);
    csmith__destroy(skeleton);
}
