// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#include "capsule_gtest.h"
#include "bpf_capsule_host.h"
#include "allocator_test.h"
#include "allocator.skel.h"

#include <array>
#include <barrier>
#include <thread>

namespace {

class AllocatorTest : public ::testing::Test {
protected:
    static constexpr unsigned threads = 8;

    void SetUp() override {
        CAPSULE_REQUIRE_BPF_PRIVILEGE();
        skel = allocator__open();
        ASSERT_NE(skel, nullptr);
        struct bpf_capsule_config config = {.fiber_count = threads, .heap_bytes = 4u << 20};
        ASSERT_EQ(bpf_capsule_configure(&capsule, skel->obj, config), 0) << strerror(errno);
        EXPECT_EQ(bpf_capsule_malloc(&capsule, 16), nullptr);
        EXPECT_EQ(errno, EINVAL);
        ASSERT_EQ(allocator__load(skel), 0);
        ASSERT_EQ(bpf_capsule_initialize(&capsule), 0);
    }

    void TearDown() override {
        EXPECT_EQ(bpf_capsule_release(&capsule), 0);
        allocator__destroy(skel);
    }

    int run(struct bpf_program* program, struct allocator_test_request* request) {
        struct bpf_test_run_opts opts = {.sz = sizeof(opts)};
        opts.ctx_in = request;
        opts.ctx_size_in = sizeof(*request);
        return capsule_test_run(bpf_program__fd(program), &opts);
    }

    struct allocator* skel = nullptr;
    struct bpf_capsule capsule = {};
};

TEST_F(AllocatorTest, HostGuestOwnership) {
    auto* bytes = static_cast<unsigned char*>(bpf_capsule_malloc(&capsule, ALLOCATOR_TEST_BYTES));
    ASSERT_NE(bytes, nullptr) << strerror(errno);
    for (unsigned i = 0; i < ALLOCATOR_TEST_BYTES; ++i) {
        bytes[i] = static_cast<unsigned char>(i);
    }
    struct allocator_test_request request = {.pointer = bytes};
    ASSERT_EQ(run(skel->progs.allocator_exchange, &request), 0);
    ASSERT_EQ(request.result.status, CAPSULE_OK);
    EXPECT_EQ(request.pointer, nullptr); // freed by the guest

    ASSERT_EQ(run(skel->progs.allocator_exchange, &request), 0);
    ASSERT_EQ(request.result.status, CAPSULE_OK);
    bytes = static_cast<unsigned char*>(request.pointer);
    ASSERT_NE(bytes, nullptr);
    for (unsigned i = 0; i < ALLOCATOR_TEST_BYTES; ++i) {
        EXPECT_EQ(bytes[i], static_cast<unsigned char>(i));
    }
    EXPECT_EQ(bpf_capsule_free(&capsule, bytes), 0); // allocated by the guest

    bytes = static_cast<unsigned char*>(bpf_capsule_malloc(&capsule, 0));
    ASSERT_NE(bytes, nullptr);
    EXPECT_EQ(bpf_capsule_free(&capsule, bytes), 0);
    EXPECT_EQ(bpf_capsule_free(&capsule, nullptr), 0);
    EXPECT_EQ(bpf_capsule_malloc(&capsule, 8u << 20), nullptr);
    EXPECT_EQ(errno, ENOMEM);
    bytes = static_cast<unsigned char*>(bpf_capsule_malloc(&capsule, 16));
    ASSERT_NE(bytes, nullptr) << "failed allocation must release its fiber";
    EXPECT_EQ(bpf_capsule_free(&capsule, bytes), 0);
}

TEST_F(AllocatorTest, ExhaustionDoesNotFreeOrReserveAFiber) {
    void* pointer = bpf_capsule_malloc(&capsule, 32);
    ASSERT_NE(pointer, nullptr);
    std::array<allocator_test_request, threads> holders = {};
    for (auto& holder : holders) {
        ASSERT_EQ(run(skel->progs.allocator_hold, &holder), 0);
        ASSERT_EQ(holder.result.status, CAPSULE_YIELD);
    }
    EXPECT_EQ(bpf_capsule_malloc(&capsule, 32), nullptr);
    EXPECT_EQ(errno, EAGAIN);
    EXPECT_EQ(bpf_capsule_free(&capsule, pointer), -1);
    EXPECT_EQ(errno, EAGAIN); // pointer is still live; free did not start
    EXPECT_EQ(bpf_capsule_free(&capsule, nullptr), 0);
    ASSERT_EQ(run(skel->progs.allocator_reset, &holders[0]), 0);
    ASSERT_EQ(holders[0].result.status, CAPSULE_OK);
    EXPECT_EQ(bpf_capsule_free(&capsule, pointer), 0);
    pointer = bpf_capsule_malloc(&capsule, 32);
    ASSERT_NE(pointer, nullptr);
    EXPECT_EQ(bpf_capsule_free(&capsule, pointer), 0);
    for (unsigned i = 1; i < threads; ++i) {
        EXPECT_EQ(run(skel->progs.allocator_reset, &holders[i]), 0);
        EXPECT_EQ(holders[i].result.status, CAPSULE_OK);
    }
}

TEST_F(AllocatorTest, ConcurrentHostAndGuestCalls) {
    std::array<std::thread, threads> workers;
    std::array<void*, threads> pointers = {};
    std::barrier phase(threads);
    for (unsigned i = 0; i < threads; ++i) {
        workers[i] = std::thread([&, i] {
            for (unsigned round = 0; round < 32; ++round) {
                if ((round & 1) && (i & 1)) {
                    struct allocator_test_request request = {};
                    EXPECT_EQ(run(skel->progs.allocator_exchange, &request), 0);
                    EXPECT_EQ(request.result.status, CAPSULE_OK);
                    pointers[i] = request.pointer;
                } else {
                    pointers[i] = bpf_capsule_malloc(&capsule, ALLOCATOR_TEST_BYTES);
                }
                EXPECT_NE(pointers[i], nullptr) << strerror(errno);
                if (pointers[i]) {
                    memset(pointers[i], i, ALLOCATOR_TEST_BYTES);
                }
                phase.arrive_and_wait();
                unsigned owner = (i + 1) % threads;
                auto* bytes = static_cast<unsigned char*>(pointers[owner]);
                if (bytes) {
                    for (unsigned j = 0; j < ALLOCATOR_TEST_BYTES; ++j) {
                        EXPECT_EQ(bytes[j], owner);
                    }
                    EXPECT_EQ(bpf_capsule_free(&capsule, bytes), 0) << strerror(errno);
                }
                phase.arrive_and_wait();
            }
        });
    }
    for (auto& worker : workers) {
        worker.join();
    }
}

} // namespace
