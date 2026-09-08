// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#include "capsule_gtest.h"
#include "bpf_capsule_host.h"
#include "integer_ops.h"
#include "integer.skel.h"
#include <algorithm>
#include <array>
#include <memory>
#include <vector>

TEST(CompilerRuntime, PlainCIntegerOperations) {
    CAPSULE_REQUIRE_BPF_PRIVILEGE();
    auto destroy = [](struct integer* p) { integer__destroy(p); };
    std::unique_ptr<struct integer, decltype(destroy)> skel(integer__open(), destroy);
    ASSERT_NE(skel, nullptr);
    bpf_capsule capsule = {};
    struct Release {
        bpf_capsule* capsule;
        ~Release() {
            bpf_capsule_release(capsule);
        }
    } release{&capsule};
    bpf_capsule_config config = {};
    config.fiber_count = 1;
    config.heap_bytes = 1 << 20;
    ASSERT_EQ(bpf_capsule_configure(&capsule, skel->obj, config), 0) << strerror(errno);
    ASSERT_EQ(integer__load(skel.get()), 0) << strerror(errno);
    ASSERT_EQ(bpf_capsule_initialize(&capsule), 0) << strerror(errno);
    constexpr size_t batch = 32;
    auto* shared = static_cast<integer_case*>(bpf_capsule_malloc(&capsule, batch * sizeof(integer_case)));
    ASSERT_NE(shared, nullptr) << strerror(errno);
    auto* state = &skel->data_integer_test->integer_state;
    state->cases = reinterpret_cast<uintptr_t>(shared);

    constexpr uint64_t words[] = {0, 1, 2, 0xffffffff, 0x100000000, 0x7fffffffffffffff, 0x8000000000000000, UINT64_MAX};
    std::vector<integer_case> cases;
    for (uint64_t a : words) {
        for (uint64_t ah : words) {
            for (uint64_t b : words) {
                for (uint64_t bh : words) {
                    cases.push_back({{a, ah}, {b, bh}, {}});
                }
            }
        }
    }
    for (uint64_t seed : {1, 7, 12345}) {
        auto random = [&] {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            return seed;
        };
        for (unsigned i = 0; i < 1024; ++i) {
            // Include the 128/64 normalization and correction paths.
            cases.push_back({{random(), random()}, {random(), i % 2 ? random() : 0}, {}});
        }
    }
    for (size_t offset = 0; offset < cases.size(); offset += batch) {
        size_t count = std::min(batch, cases.size() - offset);
        memcpy(shared, cases.data() + offset, count * sizeof(integer_case));
        state->count = count;
        ASSERT_EQ(capsule_test_run_program(skel->obj, "integer_run"), 0) << strerror(errno);
        unsigned drains = 0;
        while (state->capsule.status == CAPSULE_PENDING && drains++ < 1000) {
            ASSERT_EQ(capsule_test_run_program(skel->obj, "integer_drain"), 0) << strerror(errno);
        }
        ASSERT_EQ(state->capsule.status, unsigned(CAPSULE_OK)) << "code " << state->capsule.code;
        ASSERT_EQ(state->completed, count);
        for (size_t i = 0; i < count; ++i) {
            integer_evaluate(&cases[offset + i]);
            for (unsigned operation = 0; operation < INTEGER_RESULT_WORDS; ++operation) {
                ASSERT_EQ(shared[i].result[operation], cases[offset + i].result[operation]) << "case " << offset + i << " word " << operation;
            }
        }
    }
    EXPECT_EQ(bpf_capsule_free(&capsule, shared), 0) << strerror(errno);
}
