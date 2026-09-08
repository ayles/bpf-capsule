// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#include "capsule_gtest.h"
#include "bpf_capsule_host.h"
#include "float_ops.h"
#include "softfloat.skel.h"
#include <algorithm>
#include <array>
#include <memory>
#include <vector>

TEST(CompilerRuntime, PlainCFloatOperations) {
    CAPSULE_REQUIRE_BPF_PRIVILEGE();
    auto destroy = [](struct softfloat* p) { softfloat__destroy(p); };
    std::unique_ptr<struct softfloat, decltype(destroy)> skel(softfloat__open(), destroy);
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
    ASSERT_EQ(softfloat__load(skel.get()), 0) << strerror(errno);
    ASSERT_EQ(bpf_capsule_initialize(&capsule), 0) << strerror(errno);
    constexpr size_t batch = 64;
    auto* shared = static_cast<float_case*>(bpf_capsule_malloc(&capsule, batch * sizeof(float_case)));
    ASSERT_NE(shared, nullptr) << strerror(errno);
    auto* state = &skel->data_float_test->float_state;
    state->cases = reinterpret_cast<uintptr_t>(shared);

    // Cross-products include signed zero, NaNs, infinities, normal/subnormal
    // boundaries, cancellation and every integer-conversion boundary.
    constexpr uint64_t doubles[] = {0, 0x8000000000000000, 1, 0x8000000000000001, 0x000fffffffffffff, 0x0010000000000000, 0x3ff0000000000000,
        0xbff0000000000000, 0x3fe0000000000000, 0xbfe0000000000000, 0x3fb999999999999a, 0x4008000000000000, 0x43dfffffffffffff, 0x43e0000000000000,
        0xc3e0000000000000, 0x43efffffffffffff, 0x43f0000000000000, 0x7fefffffffffffff, 0x7ff0000000000000, 0xfff0000000000000, 0x7ff8000000000000,
        0x7ff4000000000000};
    constexpr uint32_t floats[] = {0, 0x80000000, 1, 0x80000001, 0x007fffff, 0x00800000, 0x3f800000, 0xbf800000, 0x3f000000, 0xbf000000, 0x3dcccccd, 0x40400000,
        0x5effffff, 0x5f000000, 0xdf000000, 0x5f7fffff, 0x5f800000, 0x7f7fffff, 0x7f800000, 0xff800000, 0x7fc00000, 0x7fa00000};
    static_assert(std::size(doubles) == std::size(floats));
    std::vector<float_case> cases;
    for (size_t i = 0; i < std::size(doubles); ++i) {
        for (size_t j = 0; j < std::size(doubles); ++j) {
            cases.push_back({doubles[i], doubles[j], doubles[i], floats[i], floats[j], {}});
        }
    }
    // Fixed seeds make all profiles execute exactly the same inputs.
    for (uint64_t seed : {1, 7, 12345}) {
        auto random = [&] {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            return seed;
        };
        for (unsigned i = 0; i < 4096; ++i) {
            cases.push_back({random(), random(), random(), uint32_t(random()), uint32_t(random()), {}});
        }
    }
    for (size_t offset = 0; offset < cases.size(); offset += batch) {
        size_t count = std::min(batch, cases.size() - offset);
        memcpy(shared, cases.data() + offset, count * sizeof(float_case));
        state->count = count;
        ASSERT_EQ(capsule_test_run_program(skel->obj, "float_run"), 0) << strerror(errno);
        unsigned drains = 0;
        while (state->capsule.status == CAPSULE_PENDING && drains++ < 1000) {
            ASSERT_EQ(capsule_test_run_program(skel->obj, "float_drain"), 0) << strerror(errno);
        }
        ASSERT_EQ(state->capsule.status, unsigned(CAPSULE_OK)) << "code " << state->capsule.code;
        ASSERT_EQ(state->completed, count);
        for (size_t i = 0; i < count; ++i) {
            float_evaluate(&cases[offset + i]);
            for (unsigned operation = 0; operation < FLOAT_OPERATION_COUNT; ++operation) {
                ASSERT_EQ(shared[i].result[operation], cases[offset + i].result[operation])
                    << "case " << offset + i << " operation " << operation << std::hex << " a=" << cases[offset + i].a << " b=" << cases[offset + i].b
                    << " fa=" << cases[offset + i].fa << " fb=" << cases[offset + i].fb;
            }
        }
    }
    EXPECT_EQ(bpf_capsule_free(&capsule, shared), 0) << strerror(errno);
}
