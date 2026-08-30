// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
// The yield protocol: suspension and resumption round-trips, single-use and
// generation-checked continuations, host access to a suspended fiber's stack
// state, reset semantics, and pool release on the corrupt-state path.
// (The reference host also timed 1000-rep benchmark loops; that was perf
// reporting, deliberately dropped here. The one-shot benchmark-body runs stay
// because their outputs are correctness assertions.)
#include "capsule_gtest.h"

#include "bpf_capsule_host.h"
#include "bpf_capsule_abi.h"
#include "bpf_capsule_names.h"
#include "yield_test.h"
#include "yield.skel.h"

namespace {

class YieldTest : public ::testing::Test {
protected:
    void SetUp() override {
        CAPSULE_REQUIRE_BPF_PRIVILEGE();
        skeleton_ = yield__open();
        ASSERT_NE(skeleton_, nullptr);
        struct bpf_map* config_map = bpf_object__find_map_by_name(skeleton_->obj, BPF_CAPSULE_SECTION_CONFIG);
        size_t config_size = 0;
        const struct __bpf_capsule_object_config* config =
            config_map ? (const struct __bpf_capsule_object_config*)bpf_map__initial_value(config_map, &config_size) : nullptr;
        ASSERT_NE(config, nullptr);
        ASSERT_GE(config_size, sizeof(*config));
        uses_arena_ = config->memory_backend == BPF_CAPSULE_MEMORY_ARENA;
        struct bpf_capsule_config capsule_configuration = {};
        capsule_configuration.fiber_count = 1;
        capsule_configuration.heap_bytes = 4ull << 20;
        ASSERT_EQ(bpf_capsule_configure(&capsule_, skeleton_->obj, capsule_configuration), 0) << strerror(errno);
        ASSERT_EQ(yield__load(skeleton_), 0) << strerror(errno);
        ASSERT_EQ(bpf_capsule_initialize(&capsule_), 0) << strerror(errno);
        state_ = &skeleton_->data_yieldtest->yield_test_output;
        size_t controls_size = 0;
        struct bpf_map* controls_map = bpf_object__find_map_by_name(skeleton_->obj, BPF_CAPSULE_SECTION_FIBER_CONTROLS);
        controls_ = controls_map ? (volatile struct __bpf_capsule_fiber_control*)bpf_map__initial_value(controls_map, &controls_size) : nullptr;
        controls_count_ = controls_ ? controls_size / sizeof(*controls_) : 0;
        ASSERT_NE(controls_, nullptr);
    }

    void TearDown() override {
        (void)bpf_capsule_release(&capsule_);
        yield__destroy(skeleton_);
    }

    int Run(const char* name) {
        return capsule_test_run_program(skeleton_->obj, name);
    }

    void ExpectYield(uint64_t stage, uint64_t request, uint64_t continuation) {
        EXPECT_EQ(state_->result.status, (unsigned)CAPSULE_YIELD);
        EXPECT_EQ(state_->result.code, 0);
        EXPECT_EQ(state_->result.continuation, continuation);
        EXPECT_EQ(state_->output, YIELD_TEST_SENTINEL) << "output must stay untouched until completion";
        EXPECT_EQ(state_->stage, stage);
        EXPECT_EQ(state_->request, request);
    }

    struct yield* skeleton_ = nullptr;
    struct bpf_capsule capsule_ = {};
    volatile struct yield_test_state* state_ = nullptr;
    volatile struct __bpf_capsule_fiber_control* controls_ = nullptr;
    size_t controls_count_ = 0;
    bool uses_arena_ = false;
};

TEST_F(YieldTest, Protocol) {
    ASSERT_EQ(Run("yield_test_start"), 0) << strerror(errno);
    uint64_t continuation = state_->first_continuation;
    ASSERT_NE(continuation, BPF_CAPSULE_NO_CONTINUATION);
    ExpectYield(1, 8, continuation);

    // While suspended, the fiber's live stack is host-visible Capsule memory:
    // read the guest's probe and replace it so the resumed guest checksums the
    // replacement.
    unsigned char replacement[32];
    uint64_t replacement_checksum = 0;
    for (unsigned int index = 0; index < sizeof(replacement); ++index) {
        replacement[index] = (unsigned char)(0xa0u + index);
        replacement_checksum += (uint64_t)replacement[index] * (index + 1u);
    }
    unsigned char observed[sizeof(replacement)] = {0};
    ASSERT_NE(state_->stack_probe, nullptr);
    memcpy(observed, state_->stack_probe, sizeof(observed));
    ASSERT_EQ(bpf_capsule_memcpy(&capsule_, state_->stack_probe, replacement, sizeof(replacement)), 0) << strerror(errno);
    EXPECT_NE(memcmp(observed, replacement, sizeof(observed)), 0) << "the original probe bytes differ from the replacement";

    ASSERT_EQ(Run("yield_test_first_continue"), 0) << strerror(errno);
    EXPECT_NE(state_->result.continuation, continuation) << "each yield reports a fresh continuation";
    ExpectYield(2, 54, state_->result.continuation);

    // A superseded continuation is stale even while its fiber is suspended.
    state_->stale_continuation = continuation;
    ASSERT_EQ(Run("yield_test_stale_continue"), 0) << strerror(errno);
    EXPECT_EQ(state_->stale_result.status, (unsigned)CAPSULE_EXITED);
    EXPECT_EQ(state_->stale_result.code, CAPSULE_ERROR_STALE_CONTINUATION);
    EXPECT_EQ(state_->stale_result.continuation, BPF_CAPSULE_NO_CONTINUATION);
    EXPECT_EQ(state_->result.status, (unsigned)CAPSULE_YIELD) << "the live computation is unaffected";

    ASSERT_EQ(Run("yield_test_second_continue"), 0) << strerror(errno);
    EXPECT_EQ(state_->result.status, (unsigned)CAPSULE_OK);
    EXPECT_EQ(state_->result.code, 0);
    EXPECT_EQ(state_->result.continuation, BPF_CAPSULE_NO_CONTINUATION);
    EXPECT_EQ(state_->stage, 3u);
    EXPECT_EQ(state_->output, 128u);
    EXPECT_EQ(state_->stack_probe_checksum, replacement_checksum) << "the guest resumed on the host-replaced stack bytes";

    // Stale after completion as well.
    state_->stale_continuation = continuation;
    ASSERT_EQ(Run("yield_test_stale_continue"), 0) << strerror(errno);
    EXPECT_EQ(state_->stale_result.status, (unsigned)CAPSULE_EXITED);
    EXPECT_EQ(state_->stale_result.code, CAPSULE_ERROR_STALE_CONTINUATION);

    // Re-lease the same warm fiber to unrelated work. The retired token must
    // remain stale even though its low fiber bits name an active computation.
    ASSERT_EQ(Run("yield_test_start"), 0) << strerror(errno);
    ASSERT_EQ(state_->result.status, (unsigned)CAPSULE_YIELD);
    EXPECT_NE(state_->result.continuation, continuation);
    state_->stale_continuation = continuation;
    ASSERT_EQ(Run("yield_test_stale_continue"), 0) << strerror(errno);
    EXPECT_EQ(state_->stale_result.status, (unsigned)CAPSULE_EXITED);
    EXPECT_EQ(state_->stale_result.code, CAPSULE_ERROR_STALE_CONTINUATION);
    EXPECT_EQ(state_->result.status, (unsigned)CAPSULE_YIELD);

    // Reset consumes the live continuation and releases the fiber.
    ASSERT_EQ(Run("yield_test_reset_current"), 0) << strerror(errno);
    EXPECT_EQ(state_->stale_result.status, (unsigned)CAPSULE_OK);

    // A valid token whose saved stack state is missing is terminal, and even
    // this corrupt-state path must return its only fiber to the pool. The
    // arena backend detects the missing stack while claiming the token and
    // never acquires a fiber here, so the probe is fixed-backend only.
    if (!uses_arena_) {
        ASSERT_EQ(Run("yield_test_start"), 0) << strerror(errno);
        ASSERT_EQ(state_->result.status, (unsigned)CAPSULE_YIELD);
        uint32_t fiber = (uint32_t)state_->result.continuation & 0xffffu;
        ASSERT_LT(fiber, controls_count_);
        controls_[fiber].pc = 0;
        state_->stale_continuation = state_->result.continuation;
        ASSERT_EQ(Run("yield_test_stale_continue"), 0) << strerror(errno);
        EXPECT_EQ(state_->stale_result.status, (unsigned)CAPSULE_EXITED);
        EXPECT_EQ(state_->stale_result.code, CAPSULE_ERROR_NOT_PENDING);
        EXPECT_EQ(state_->stale_result.continuation, BPF_CAPSULE_NO_CONTINUATION);
    }

    // The yielding and non-yielding benchmark bodies must both complete and
    // agree on the round-trip sum (8 rounds of request*2).
    ASSERT_EQ(Run("yield_baseline_run"), 0) << strerror(errno);
    EXPECT_EQ(state_->benchmark_result.status, (unsigned)CAPSULE_OK);
    EXPECT_EQ(state_->benchmark_output, 72u);
    ASSERT_EQ(Run("yield_benchmark_run"), 0) << strerror(errno);
    EXPECT_EQ(state_->benchmark_result.status, (unsigned)CAPSULE_OK);
    EXPECT_EQ(state_->benchmark_output, 72u);
}

} // namespace
