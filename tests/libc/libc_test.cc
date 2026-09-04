// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
// Picolibc under the transform: stdio and its replaceable platform,
// integer/float conversion, libm edge cases, and allocator failure when no
// heap is configured.
#include "capsule_gtest.h"

#include "bpf_capsule_host.h"
#include "libc_test.h"
#include "libc.skel.h"

TEST(Libc, PicolibcContracts) {
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

    EXPECT_EQ(result->capsule.status, (unsigned)CAPSULE_EXITED);
    EXPECT_EQ(result->capsule.code, 37u);
    EXPECT_EQ(result->atexit_calls, 1u);
    EXPECT_EQ(result->failures, 0u) << "guest-side failure bitmap: 0x" << std::hex << result->failures;
    EXPECT_EQ(result->truncated_length, 20) << "snprintf reports the untruncated length";
    EXPECT_STREQ((const char*)result->truncated, "-922");
    const char* expected = "-7/-32000/-9/-9223372036854775808/17/-9223372036854775808/0x00002a/011/  Q/xy   /abc/%";
    EXPECT_EQ(result->formatted_length, (int)strlen(expected));
    EXPECT_STREQ((const char*)result->formatted, expected);
    const char* expectedFloats = "12.5/+1.25/1.234e+03/0x1.8p+1/0X1.999999999999AP-4/2/2./inf/NAN";
    EXPECT_EQ(result->float_length, (int)strlen(expectedFloats));
    EXPECT_STREQ((const char*)result->floats, expectedFloats);
    // Picolibc emits the shortest decimal spelling that round-trips to the same double.
    const char* expectedFloatEdges = "5e-324|1.7976931348623157e+308|-000001.50|0x1.p+0|4|-0|1e+03|0.0001";
    EXPECT_EQ(result->float_edge_length, (int)strlen(expectedFloatEdges));
    EXPECT_STREQ((const char*)result->float_edges, expectedFloatEdges);
    EXPECT_EQ(result->parsed_max, ~0ull);
    EXPECT_EQ(result->parsed_overflow, ~0ull);
    EXPECT_EQ(result->parsed_negative, ~0ull);
    EXPECT_EQ(result->parsed_min, -9223372036854775807l - 1l);
    EXPECT_EQ(result->overflow_errno, (unsigned)ERANGE);
    EXPECT_EQ(result->printed_result, 16);
    EXPECT_EQ(result->printed_length, 16u);
    EXPECT_EQ(std::string((const char*)result->printed, result->printed_length), "capsule stdio 17");

    EXPECT_EQ(bpf_capsule_release(&capsule), 0) << strerror(errno);
    libc__destroy(skeleton);
}
