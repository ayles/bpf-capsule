// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
// Verifier-pointer discipline: helper results and their GEPs stay
// verifier-native and are consumed before the region returns to the
// trampoline, while scalars loaded from the context may cross managed-call
// boundaries.
#include "capsule_gtest.h"

#include "bpf_capsule_host.h"
#include "verifier_pointer_test.h"
#include "verifier_pointer.skel.h"

#include <net/if.h>

TEST(VerifierPointer, HelperPointersStayNativeScalarsCross) {
    CAPSULE_REQUIRE_BPF_PRIVILEGE();
    struct verifier_pointer* skeleton = verifier_pointer__open();
    ASSERT_NE(skeleton, nullptr);
    struct bpf_capsule capsule = {};
    struct bpf_capsule_config capsule_configuration = {};
    capsule_configuration.fiber_count = 1;
    capsule_configuration.heap_bytes = 4ull << 20;
    ASSERT_EQ(bpf_capsule_configure(&capsule, skeleton->obj, capsule_configuration), 0) << strerror(errno);
    ASSERT_EQ(verifier_pointer__load(skeleton), 0) << strerror(errno);
    ASSERT_EQ(bpf_capsule_initialize(&capsule), 0) << strerror(errno);

    const unsigned int key = 0;
    const struct verifier_pointer_map_value initial = {0x1020304050607080ull, 0xa1b2c3d4e5f60718ull};
    struct verifier_pointer_map_value final_value = {};
    struct bpf_map* values = bpf_object__find_map_by_name(skeleton->obj, "vpointer_values");
    ASSERT_NE(values, nullptr);
    ASSERT_EQ(bpf_map_update_elem(bpf_map__fd(values), &key, &initial, BPF_ANY), 0);

    volatile struct verifier_pointer_result* output = &skeleton->data_vpointer->verifier_pointer_output;
    const unsigned char packet[64] = {0};
    // Linux 5.15 requires a supplied XDP context's data_end to match the
    // packet length; device fields stay zero (no registered RX queue needed).
    struct xdp_md context = {};
    context.data_end = sizeof(packet);
    struct bpf_test_run_opts options = {};
    options.sz = sizeof(options);
    options.data_in = packet;
    options.data_size_in = sizeof(packet);
    options.ctx_in = &context;
    options.ctx_size_in = sizeof(context);
    ASSERT_EQ(capsule_test_run(bpf_program__fd(skeleton->progs.verifier_pointer_run), &options), 0) << strerror(errno);

    ASSERT_EQ(bpf_map_lookup_elem(bpf_map__fd(values), &key, &final_value), 0);
    EXPECT_EQ(output->capsule.status, (unsigned)CAPSULE_OK);
    EXPECT_EQ(output->capsule.code, 0);
    EXPECT_EQ(output->value.previous, initial.value);
    EXPECT_EQ(output->value.observed, 0x1122334455667788ull);
    EXPECT_EQ(output->value.guard, initial.guard) << "the adjacent map word stayed untouched";
    // The kernel populates ingress_ifindex (loopback) even for a zeroed
    // ctx_in, so scalar_transform(ingress)+scalar_transform(queue) yields
    // (3*ifindex+1) + (3*0+1) + 1 + 1.
    unsigned int ingress_ifindex = if_nametoindex("lo");
    ASSERT_NE(ingress_ifindex, 0u);
    EXPECT_EQ(output->value.context_scalar, (uint64_t)ingress_ifindex * 3 + 4);
    EXPECT_EQ(final_value.value, output->value.observed);
    EXPECT_EQ(final_value.guard, initial.guard);

    EXPECT_EQ(bpf_capsule_release(&capsule), 0) << strerror(errno);
    verifier_pointer__destroy(skeleton);
}
