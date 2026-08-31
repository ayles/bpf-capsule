// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
// A context call can read packet bytes directly, and the same hidden context
// is available again when a voluntary yield is resumed through
// capsule_continue_ctx. Both paths must produce the identical checksum. The
// non-yielding object additionally proves scalar and context roots dispatch
// through one object.
#include "capsule_gtest.h"

#include "bpf_capsule_host.h"
#include "context_interop_test.h"
#include "ctx_borrowed.skel.h"
#include "ctx_yield.skel.h"

namespace {

uint64_t expected_checksum(const unsigned char* packet) {
    uint64_t checksum = CONTEXT_INTEROP_FNV_OFFSET;
    for (unsigned int index = 0; index < CONTEXT_INTEROP_BYTES; ++index) {
        checksum = (checksum ^ packet[index]) * CONTEXT_INTEROP_FNV_PRIME;
    }
    return checksum;
}

uint64_t expected_scalar() {
    uint64_t value = 0x123456789abcdef0ull;
    for (unsigned int index = 0; index < 64; ++index) {
        value = value * 33 + index;
    }
    return value;
}

void fill_packet(unsigned char* packet) {
    for (unsigned int index = 0; index < CONTEXT_INTEROP_BYTES; ++index) {
        packet[index] = (unsigned char)(index * 37 + 11);
    }
}

int run_policy(int fd, const unsigned char* packet, unsigned int* action) {
    unsigned char output[CONTEXT_INTEROP_BYTES] = {0};
    struct bpf_test_run_opts options = {};
    options.sz = sizeof(options);
    options.data_in = packet;
    options.data_size_in = CONTEXT_INTEROP_BYTES;
    options.data_out = output;
    options.data_size_out = sizeof(output);
    options.repeat = 1;
    if (bpf_prog_test_run_opts(fd, &options)) {
        return -1;
    }
    *action = options.retval;
    return 0;
}

TEST(ContextInterop, BorrowedAndYieldAgree) {
    CAPSULE_REQUIRE_BPF_PRIVILEGE();
    unsigned char packet[CONTEXT_INTEROP_BYTES];
    fill_packet(packet);
    uint64_t borrowed_checksum = 0;
    uint64_t yield_checksum = 0;

    {
        struct ctx_borrowed* skeleton = ctx_borrowed__open();
        ASSERT_NE(skeleton, nullptr);
        struct bpf_capsule capsule = {};
        struct bpf_capsule_config capsule_configuration = {};
        capsule_configuration.fiber_count = 1;
        capsule_configuration.heap_bytes = 4ull << 20;
        ASSERT_EQ(bpf_capsule_configure(&capsule, skeleton->obj, capsule_configuration), 0) << strerror(errno);
        ASSERT_EQ(ctx_borrowed__load(skeleton), 0) << strerror(errno);
        ASSERT_EQ(bpf_capsule_initialize(&capsule), 0) << strerror(errno);

        // Scalar and context roots share the object: the scalar root must
        // dispatch correctly before and independently of the context one.
        size_t scalar_size = 0;
        volatile struct context_interop_scalar_output* scalar =
            (volatile struct context_interop_scalar_output*)capsule_test_global(skeleton->obj, "context_interop_scalar_output", &scalar_size);
        ASSERT_NE(scalar, nullptr);
        ASSERT_GE(scalar_size, sizeof(*scalar));
        struct bpf_program* scalar_run = bpf_object__find_program_by_name(skeleton->obj, "context_interop_scalar_run");
        struct bpf_program* scalar_drain = bpf_object__find_program_by_name(skeleton->obj, "context_interop_scalar_drain");
        ASSERT_NE(scalar_run, nullptr);
        ASSERT_NE(scalar_drain, nullptr);
        struct bpf_test_run_opts scalar_options = {};
        scalar_options.sz = sizeof(scalar_options);
        ASSERT_EQ(capsule_test_drive(bpf_program__fd(scalar_run), bpf_program__fd(scalar_drain), &scalar_options, 1000, nullptr, nullptr, &scalar->capsule), 0)
            << strerror(errno);
        EXPECT_EQ(scalar->capsule.status, (unsigned)CAPSULE_OK);
        EXPECT_EQ(scalar->capsule.code, 0);
        EXPECT_EQ(scalar->value, expected_scalar());

        volatile struct context_interop_output* output = &skeleton->data_ctxinterop->context_interop_result;
        unsigned int action = 0;
        ASSERT_EQ(run_policy(bpf_program__fd(skeleton->progs.context_interop_run), packet, &action), 0) << strerror(errno);
        EXPECT_EQ(action, (unsigned)XDP_PASS);
        EXPECT_EQ(output->capsule.status, (unsigned)CAPSULE_OK);
        EXPECT_EQ(output->capsule.code, 0);
        EXPECT_EQ(output->protocol_error, 0u);
        EXPECT_EQ(output->copied, (unsigned)CONTEXT_INTEROP_BYTES);
        EXPECT_EQ(output->checksum, expected_checksum(packet));
        borrowed_checksum = output->checksum;
        EXPECT_EQ(bpf_capsule_release(&capsule), 0) << strerror(errno);
        ctx_borrowed__destroy(skeleton);
    }

    {
        struct ctx_yield* skeleton = ctx_yield__open();
        ASSERT_NE(skeleton, nullptr);
        struct bpf_capsule capsule = {};
        struct bpf_capsule_config capsule_configuration = {};
        capsule_configuration.fiber_count = 1;
        capsule_configuration.heap_bytes = 4ull << 20;
        ASSERT_EQ(bpf_capsule_configure(&capsule, skeleton->obj, capsule_configuration), 0) << strerror(errno);
        ASSERT_EQ(ctx_yield__load(skeleton), 0) << strerror(errno);
        ASSERT_EQ(bpf_capsule_initialize(&capsule), 0) << strerror(errno);
        volatile struct context_interop_output* output = &skeleton->data_ctxinterop->context_interop_result;
        unsigned int action = 0;
        ASSERT_EQ(run_policy(bpf_program__fd(skeleton->progs.context_interop_run), packet, &action), 0) << strerror(errno);
        EXPECT_EQ(action, (unsigned)XDP_PASS);
        EXPECT_EQ(output->capsule.status, (unsigned)CAPSULE_OK);
        EXPECT_EQ(output->capsule.code, 0);
        EXPECT_EQ(output->protocol_error, 0u);
        EXPECT_EQ(output->copied, (unsigned)CONTEXT_INTEROP_BYTES);
        EXPECT_EQ(output->checksum, expected_checksum(packet));
        yield_checksum = output->checksum;
        EXPECT_EQ(bpf_capsule_release(&capsule), 0) << strerror(errno);
        ctx_yield__destroy(skeleton);
    }

    EXPECT_EQ(borrowed_checksum, yield_checksum);
}

} // namespace
