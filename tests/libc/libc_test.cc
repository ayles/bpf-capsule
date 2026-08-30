// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
// Freestanding libc under the transform: printf formatting incl. truncation,
// strtoull/strtol edge cases, soft-float special values, and the null
// allocator (no heap configured -> malloc reports ENOMEM).
#include "capsule_gtest.h"

#include "bpf_capsule_host.h"
#include "libc_test.h"
#include "libc.skel.h"

TEST(Libc, FreestandingContracts) {
    CAPSULE_REQUIRE_BPF_PRIVILEGE();
    struct libc* skeleton = libc__open();
    ASSERT_NE(skeleton, nullptr);
    struct bpf_capsule capsule = {};
    struct bpf_capsule_config config = {};
    config.fiber_count = 1;
    ASSERT_EQ(bpf_capsule_configure(&capsule, skeleton->obj, config), 0) << strerror(errno);
    ASSERT_EQ(libc__load(skeleton), 0) << strerror(errno);
    ASSERT_EQ(bpf_capsule_initialize(&capsule), 0) << strerror(errno);

    size_t size = 0;
    volatile struct libc_test_result* result = (volatile struct libc_test_result*)capsule_test_global(skeleton->obj, "libc_test_output", &size);
    ASSERT_NE(result, nullptr);
    ASSERT_GE(size, sizeof(*result));

    struct bpf_program* entry = bpf_object__find_program_by_name(skeleton->obj, "libc_test_run");
    struct bpf_program* drain = bpf_object__find_program_by_name(skeleton->obj, "libc_test_continue");
    ASSERT_NE(entry, nullptr);
    ASSERT_NE(drain, nullptr);
    struct bpf_test_run_opts options = {};
    options.sz = sizeof(options);
    ASSERT_EQ(capsule_test_drive(bpf_program__fd(entry), bpf_program__fd(drain), &options, 100000, nullptr, nullptr, &result->capsule), 0) << strerror(errno);

    EXPECT_EQ(result->capsule.status, (unsigned)CAPSULE_OK);
    EXPECT_EQ(result->failures, 0u) << "guest-side failure bitmap: 0x" << std::hex << result->failures;
    EXPECT_EQ(result->truncated_length, 20) << "snprintf reports the untruncated length";
    EXPECT_STREQ((const char*)result->truncated, "-922");
    const char* expected = "-7/-32000/-9/-9223372036854775808/17/-9223372036854775808/0x00002a/011/  Q/xy   /abc/%";
    EXPECT_EQ(result->formatted_length, (int)strlen(expected));
    EXPECT_STREQ((const char*)result->formatted, expected);
    EXPECT_EQ(result->parsed_max, ~0ull);
    EXPECT_EQ(result->parsed_overflow, ~0ull);
    EXPECT_EQ(result->parsed_negative, ~0ull);
    EXPECT_EQ(result->parsed_min, -9223372036854775807l - 1l);
    EXPECT_EQ(result->overflow_errno, (unsigned)ERANGE);

    EXPECT_EQ(bpf_capsule_release(&capsule), 0) << strerror(errno);
    libc__destroy(skeleton);
}
