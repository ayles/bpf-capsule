// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
// The broad compiler integration fixture (drive level 2, 2 fibers): core
// semantics (recursion, indirect calls, tail frame replacement, aggregates,
// overflow intrinsics, sparse-arena pointers, large copies, parallel PHIs,
// managed atomics), the runtime guards (VLA bound, exit
// contract), aggregate returns across suspension, fiber isolation, and the
// shared TLSF allocator under two-CPU concurrency.
#include "capsule_gtest.h"

#include "bpf_capsule_host.h"
#include "compiler_test.h"
#include "compiler.skel.h"

#include <pthread.h>
#include <sched.h>

namespace {

struct compiler_return_value expected_return(unsigned int seed) {
    struct compiler_return_value value = {};
    value.wide = 0x9e3779b97f4a7c15ull ^ seed;
    value.word = 0x6a09e667u + seed * 17u;
    value.half = (unsigned short)(0xbb67u ^ seed);
    for (unsigned int index = 0; index < sizeof(value.bytes); ++index) {
        value.bytes[index] = (unsigned char)(seed + index * 13u);
    }
    return value;
}

void expect_return_equal(volatile const struct compiler_return_value* observed, const struct compiler_return_value* expected) {
    EXPECT_EQ(observed->wide, expected->wide);
    EXPECT_EQ(observed->word, expected->word);
    EXPECT_EQ(observed->half, expected->half);
    for (unsigned int index = 0; index < sizeof(expected->bytes); ++index) {
        EXPECT_EQ(observed->bytes[index], expected->bytes[index]) << "byte " << index;
    }
}

class CompilerTest : public ::testing::Test {
protected:
    void SetUp() override {
        CAPSULE_REQUIRE_BPF_PRIVILEGE();
        skeleton_ = compiler__open();
        ASSERT_NE(skeleton_, nullptr);
        struct bpf_capsule_config config = {};
        config.fiber_count = 2;
        config.heap_bytes = 4ull << 20;
        ASSERT_EQ(bpf_capsule_configure(&capsule_, skeleton_->obj, config), 0) << strerror(errno);
        ASSERT_EQ(compiler__load(skeleton_), 0) << strerror(errno);
        ASSERT_EQ(bpf_capsule_initialize(&capsule_), 0) << strerror(errno);
    }

    void TearDown() override {
        (void)bpf_capsule_release(&capsule_);
        compiler__destroy(skeleton_);
    }

    int Run(const char* name) {
        return capsule_test_run_program(skeleton_->obj, name);
    }

    struct compiler* skeleton_ = nullptr;
    struct bpf_capsule capsule_ = {};
};

TEST_F(CompilerTest, CoreSemantics) {
    // A Capsule boundary in an ordinary native helper, two wrappers deep.
    ASSERT_EQ(Run("compiler_nested_capsule_run"), 0) << strerror(errno);

    volatile struct compiler_test_result* result = &skeleton_->data_ctres->compiler_result;
    ASSERT_EQ(Run("compiler_test_run"), 0) << strerror(errno);
    unsigned long drains = 0;
    while (result->pending && !result->code) {
        ASSERT_LT(drains, 1000000u) << "drain cap exceeded";
        ASSERT_EQ(Run("compiler_test_drain"), 0) << strerror(errno);
        drains++;
    }
    EXPECT_EQ(result->failures, 0u) << "guest failure bitmap 0x" << std::hex << result->failures;
    EXPECT_EQ(result->checksum, 0xfc2480581a29b119ull);
    EXPECT_EQ(result->pending, 0u);
    EXPECT_EQ(result->code, 0);
    EXPECT_EQ(result->sparse_pointer_difference, 34);
    EXPECT_EQ(result->initialized_pointer_difference, 7);
    EXPECT_EQ(result->copy_failures, 0u);
    EXPECT_EQ(result->memset_failures, 0u);
    EXPECT_EQ(result->parallel_phi_sum, 297u);
    EXPECT_EQ(result->varargs_value, 1221u);

    // The verifier-native entry uses the real BPF atomic ISA.
    ASSERT_EQ(Run("compiler_native_atomic_run"), 0) << strerror(errno);
    EXPECT_EQ(result->native_atomic_failures, 0u);
}

TEST_F(CompilerTest, RuntimeGuards) {
    volatile struct compiler_guard_result* guards = &skeleton_->data_ctguard->compiler_guards;

    // The llvm.sqrt.f64 intrinsic spelling lowers to the same libm sqrt an
    // ordinary call reaches: the body completes normally with the real
    // result.
    ASSERT_EQ(Run("compiler_fp_intrinsic_run"), 0) << strerror(errno);
    for (int drives = 0; guards->intrinsic_status == (unsigned)CAPSULE_PENDING && drives < 10000; drives++) {
        ASSERT_EQ(Run("compiler_fp_intrinsic_run"), 0) << strerror(errno);
    }
    EXPECT_EQ(guards->intrinsic_status, (unsigned)CAPSULE_OK);
    EXPECT_EQ(guards->intrinsic_after, 1u);
    EXPECT_EQ(guards->intrinsic_value, 3u);

    // A 4 KiB VLA is a real run-time carving below the frame; both ends
    // must be addressable and the body completes.
    ASSERT_EQ(Run("compiler_vla_guard_run"), 0) << strerror(errno);
    EXPECT_EQ(guards->vla_before, 1u);
    EXPECT_EQ(guards->vla_after, 1u);
    EXPECT_EQ(guards->vla_status, (unsigned)CAPSULE_OK);

    // A VLA larger than the fiber stack aborts at the carving bound before
    // anything is touched.
    skeleton_->data_ctin->compiler_vla_count = 1u << 20;
    ASSERT_EQ(Run("compiler_vla_guard_run"), 0) << strerror(errno);
    EXPECT_EQ(guards->vla_after, 0u);
    EXPECT_EQ(guards->vla_status, (unsigned)CAPSULE_EXITED);
    EXPECT_EQ(guards->vla_code, CAPSULE_ERROR_STACK_OVERFLOW);

    // capsule_exit(-37) masks with 0xff exactly as POSIX observes an exit
    // status (219); the exiting call reclaims only its own fiber.
    ASSERT_EQ(Run("compiler_exit_contract_run"), 0) << strerror(errno);
    EXPECT_EQ(guards->exit_held_status, (unsigned)CAPSULE_PENDING);
    EXPECT_EQ(guards->exit_status, (unsigned)CAPSULE_EXITED);
    EXPECT_EQ(guards->exit_code, 219);
    EXPECT_EQ(guards->exit_after, 0u);
    EXPECT_EQ(guards->exit_reuse_status, (unsigned)CAPSULE_OK);
    EXPECT_EQ(guards->exit_reset_status, (unsigned)CAPSULE_OK);

    // Clang's ordinary `llvm.trap; unreachable` shape must terminate with
    // TRAP exactly once. It must neither execute the suffix nor be overwritten
    // by the raw-unreachable fallback.
    ASSERT_EQ(Run("compiler_trap_contract_run"), 0) << strerror(errno);
    EXPECT_EQ(guards->trap_status, (unsigned)CAPSULE_EXITED);
    EXPECT_EQ(guards->trap_code, CAPSULE_ERROR_TRAP);
    EXPECT_EQ(guards->trap_after, 0u);

    ASSERT_EQ(Run("compiler_jump_run"), 0) << strerror(errno);
    for (int drives = 0; guards->jump_capsule.status == (unsigned)CAPSULE_PENDING && drives < 10000; drives++) {
        ASSERT_EQ(Run("compiler_jump_run"), 0) << strerror(errno);
    }
    EXPECT_EQ(guards->jump_capsule.status, (unsigned)CAPSULE_OK);
    EXPECT_EQ(guards->jump_capsule.code, 0);
    EXPECT_EQ(guards->jump_value, 371);
}

TEST_F(CompilerTest, AggregateReturns) {
    volatile struct compiler_return_result* returns = &skeleton_->data_ctreturn->compiler_returns;

    ASSERT_EQ(Run("compiler_return_immediate_run"), 0) << strerror(errno);
    struct compiler_return_value immediate = expected_return(0x1234u);
    EXPECT_EQ(returns->immediate_capsule.status, (unsigned)CAPSULE_OK);
    EXPECT_EQ(returns->immediate_capsule.code, 0);
    expect_return_equal(&returns->immediate, &immediate);

    // A suspended computation must not touch the output until CAPSULE_OK.
    ASSERT_EQ(Run("compiler_return_suspended_run"), 0) << strerror(errno);
    EXPECT_EQ(returns->suspended_capsule.status, (unsigned)CAPSULE_PENDING) << "the drive level must leave this body suspended";
    EXPECT_NE(returns->pending_output_unchanged, 0u);
    unsigned int drains = 0;
    while (returns->suspended_capsule.status == CAPSULE_PENDING && drains++ < 10000) {
        ASSERT_EQ(Run("compiler_return_suspended_drain"), 0) << strerror(errno);
    }
    ASSERT_LT(drains, 10000u);
    unsigned int seed = 0x5678u;
    for (unsigned int index = 0; index < 512; ++index) {
        seed = seed * 33u + 17u;
    }
    struct compiler_return_value suspended = expected_return(seed);
    EXPECT_EQ(returns->suspended_capsule.status, (unsigned)CAPSULE_OK);
    EXPECT_EQ(returns->suspended_capsule.code, 0);
    expect_return_equal(&returns->suspended, &suspended);
}

TEST_F(CompilerTest, FiberIsolation) {
    volatile struct compiler_fiber_result* fibers = &skeleton_->data_ctfiber->compiler_fibers;

    ASSERT_EQ(Run("compiler_fiber_start"), 0) << strerror(errno);
    unsigned int drains = 0;
    while (fibers->other_status == CAPSULE_PENDING && drains++ < 10000) {
        ASSERT_EQ(Run("compiler_fiber_other"), 0) << strerror(errno);
    }
    while (fibers->resume_status == CAPSULE_PENDING && drains++ < 10000) {
        ASSERT_EQ(Run("compiler_fiber_resume"), 0) << strerror(errno);
    }
    ASSERT_LT(drains, 10000u);

    EXPECT_EQ(fibers->start_status, (unsigned)CAPSULE_PENDING);
    EXPECT_EQ(fibers->second_start_status, (unsigned)CAPSULE_PENDING);
    EXPECT_EQ(fibers->other_status, (unsigned)CAPSULE_OK);
    EXPECT_EQ(fibers->resume_status, (unsigned)CAPSULE_OK);
    EXPECT_EQ(fibers->exhausted_status, (unsigned)CAPSULE_EXITED) << "a third call on two fibers reports pool exhaustion";
    EXPECT_EQ(fibers->exhausted_code, CAPSULE_ERROR_POOL_EXHAUSTED);
    EXPECT_NE(fibers->first_fiber, fibers->second_fiber) << "simultaneous computations lease distinct fibers";
    EXPECT_EQ(fibers->reset_status, (unsigned)CAPSULE_OK);
    EXPECT_EQ(fibers->after_reset_status, (unsigned)CAPSULE_OK);
    EXPECT_NE(fibers->reset_fiber, BPF_CAPSULE_NO_CONTINUATION);
    EXPECT_LT(fibers->after_reset_fiber, 2u);
    EXPECT_NE(fibers->paused_pending, 0u);
    EXPECT_EQ(fibers->paused_code, 0);
    // Each fiber's addressable local survived the other fiber's execution.
    EXPECT_EQ(fibers->other_value, 0xa5u);
    EXPECT_EQ(fibers->resumed_value, 0x5au);
}

struct allocator_gate {
    pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
    pthread_cond_t condition = PTHREAD_COND_INITIALIZER;
    unsigned ready = 0;
    int released = 0;
    int cancelled = 0;
};

struct allocator_thread {
    int run_fd;
    int drain_fd;
    int cpu;
    unsigned lane;
    volatile struct compiler_allocator_result* result;
    pthread_barrier_t* start;
    allocator_gate* gate;
    int error;
    unsigned long invocations;
    unsigned completed;
};

int allocator_wait_for_start(allocator_gate* gate) {
    pthread_mutex_lock(&gate->mutex);
    gate->ready++;
    pthread_cond_broadcast(&gate->condition);
    while (!gate->released) {
        pthread_cond_wait(&gate->condition, &gate->mutex);
    }
    int run = !gate->cancelled;
    pthread_mutex_unlock(&gate->mutex);
    return run;
}

void allocator_release_workers(allocator_gate* gate, int cancelled) {
    pthread_mutex_lock(&gate->mutex);
    while (!cancelled && gate->ready != 2) {
        pthread_cond_wait(&gate->condition, &gate->mutex);
    }
    gate->cancelled = cancelled;
    gate->released = 1;
    pthread_cond_broadcast(&gate->condition);
    pthread_mutex_unlock(&gate->mutex);
}

void* run_allocator_thread(void* argument) {
    allocator_thread* thread = (allocator_thread*)argument;
    struct bpf_test_run_opts options = {};
    options.sz = sizeof(options);
    cpu_set_t affinity;
    CPU_ZERO(&affinity);
    CPU_SET(thread->cpu, &affinity);
    thread->error = pthread_setaffinity_np(pthread_self(), sizeof(affinity), &affinity);
    if (!allocator_wait_for_start(thread->gate) || thread->error) {
        return nullptr;
    }
    for (unsigned repetition = 0; repetition < 8; ++repetition) {
        pthread_barrier_wait(thread->start);
        if (!thread->error) {
            thread->error = capsule_test_run(thread->run_fd, &options);
            thread->invocations++;
        }
        // Hold both entry continuations before either worker drains: two
        // simultaneous computations must receive distinct leases even when
        // the free pool reuses the warmest fiber first.
        pthread_barrier_wait(thread->start);
        if (thread->error) {
            continue;
        }
        unsigned long drains = 0;
        while (!thread->error && thread->result->capsule[thread->lane].status == CAPSULE_PENDING) {
            if (drains++ >= 100000) {
                thread->error = -1;
                break;
            }
            thread->error = capsule_test_run(thread->drain_fd, &options);
            thread->invocations++;
        }
        if (!thread->error && thread->result->capsule[thread->lane].status != CAPSULE_OK) {
            thread->error = -1;
        }
        if (!thread->error && thread->result->failures[thread->lane] == 0 && thread->result->operations[thread->lane] == 624) {
            thread->completed++;
        } else if (!thread->error) {
            thread->error = -1;
        }
    }
    return nullptr;
}

TEST_F(CompilerTest, AllocatorConcurrency) {
    volatile struct compiler_allocator_result* allocator = &skeleton_->data_ctalloc->compiler_allocator;

    cpu_set_t allowed;
    int cpus[2] = {-1, -1};
    unsigned cpu_count = 0;
    ASSERT_EQ(sched_getaffinity(0, sizeof(allowed), &allowed), 0);
    for (int cpu = 0; cpu < CPU_SETSIZE && cpu_count < 2; ++cpu) {
        if (CPU_ISSET(cpu, &allowed)) {
            cpus[cpu_count++] = cpu;
        }
    }
    ASSERT_EQ(cpu_count, 2u) << "the allocator concurrency check needs two CPUs";

    pthread_barrier_t start;
    ASSERT_EQ(pthread_barrier_init(&start, nullptr, 2), 0);
    allocator_gate gate;
    allocator_thread threads[2] = {};
    threads[0] = {bpf_program__fd(skeleton_->progs.compiler_allocator_run0), bpf_program__fd(skeleton_->progs.compiler_allocator_drain0), cpus[0], 0, allocator,
        &start, &gate, 0, 0, 0};
    threads[1] = {bpf_program__fd(skeleton_->progs.compiler_allocator_run1), bpf_program__fd(skeleton_->progs.compiler_allocator_drain1), cpus[1], 1, allocator,
        &start, &gate, 0, 0, 0};
    pthread_t ids[2];
    int create0 = pthread_create(&ids[0], nullptr, run_allocator_thread, &threads[0]);
    int create1 = pthread_create(&ids[1], nullptr, run_allocator_thread, &threads[1]);
    allocator_release_workers(&gate, create0 || create1);
    if (!create0) {
        pthread_join(ids[0], nullptr);
    }
    if (!create1) {
        pthread_join(ids[1], nullptr);
    }
    pthread_barrier_destroy(&start);

    ASSERT_EQ(create0, 0);
    ASSERT_EQ(create1, 0);
    EXPECT_EQ(threads[0].error, 0) << "status " << allocator->capsule[0].status << ", code " << allocator->capsule[0].code << ", total invocations "
                                   << threads[0].invocations;
    EXPECT_EQ(threads[1].error, 0) << "status " << allocator->capsule[1].status << ", code " << allocator->capsule[1].code << ", total invocations "
                                   << threads[1].invocations;
    EXPECT_EQ(allocator->failures[0], 0u) << "lane 0 failure bitmap 0x" << std::hex << allocator->failures[0];
    EXPECT_EQ(allocator->failures[1], 0u) << "lane 1 failure bitmap 0x" << std::hex << allocator->failures[1];
    EXPECT_NE(allocator->first_fiber[0], BPF_CAPSULE_NO_CONTINUATION);
    EXPECT_NE(allocator->first_fiber[1], BPF_CAPSULE_NO_CONTINUATION);
    EXPECT_NE(allocator->first_fiber[0], allocator->first_fiber[1]);
    EXPECT_EQ(threads[0].completed, 8u);
    EXPECT_EQ(threads[1].completed, 8u);
    EXPECT_EQ(allocator->operations[0], 624u);
    EXPECT_EQ(allocator->operations[1], 624u);
}

} // namespace
