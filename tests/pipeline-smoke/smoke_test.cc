// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#include "capsule_gtest.h"

#include "bpf_capsule_host.h"
#include "smoke.h"
#include "smoke.skel.h"

TEST(PipelineSmoke, RecursiveFibComputesInKernel) {
    CAPSULE_REQUIRE_BPF_PRIVILEGE();
    struct smoke* skeleton = smoke__open();
    ASSERT_NE(skeleton, nullptr);
    struct bpf_capsule capsule = {};
    struct bpf_capsule_config config = {};
    config.fiber_count = 1;
    ASSERT_EQ(bpf_capsule_configure(&capsule, skeleton->obj, config), 0) << strerror(errno);
    ASSERT_EQ(smoke__load(skeleton), 0) << "smoke object did not load: " << strerror(errno);
    ASSERT_EQ(bpf_capsule_initialize(&capsule), 0) << strerror(errno);

    volatile auto* state = &skeleton->data_smoke->smoke_state;
    state->input = 20;
    ASSERT_EQ(capsule_test_run_program(skeleton->obj, "smoke_run"), 0) << strerror(errno);
    unsigned drains = 0;
    while (state->capsule.status == CAPSULE_PENDING && drains++ < 100000) {
        ASSERT_EQ(capsule_test_run_program(skeleton->obj, "smoke_drain"), 0) << strerror(errno);
    }
    const volatile auto* control = &skeleton->bss_bpfctrl->bpf_capsule_fibers[0];
    ASSERT_EQ(state->capsule.status, (unsigned)CAPSULE_OK)
        << "code " << state->capsule.code << ", pc " << control->pc << ", sp " << control->sp << ", fp " << control->fp;
    EXPECT_EQ(state->output, 6765u) << "fib(20)";

    EXPECT_EQ(bpf_capsule_release(&capsule), 0) << strerror(errno);
    smoke__destroy(skeleton);
}
