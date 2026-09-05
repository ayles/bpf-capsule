// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
// Runtime atomics: a verifier-native entry increments with real BPF atomic
// ISA from several CPUs at once, and managed code's relaxed load/store subset
// stays tearing-free across widths under a concurrent writer/reader pair.
#include "capsule_gtest.h"

#include "bpf_capsule_host.h"
#include "native.h"
#include "atomics.skel.h"

#include <pthread.h>
#include <sched.h>

namespace {

constexpr unsigned kThreads = 4;
constexpr unsigned kIterations = 256;

struct start_gate {
    pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
    pthread_cond_t condition = PTHREAD_COND_INITIALIZER;
    unsigned ready = 0;
    int released = 0;
    int cancelled = 0;
};

struct worker {
    start_gate* gate;
    int program_fd;
    int cpu;
    unsigned iterations;
    int error;
};

int wait_for_start(start_gate* gate) {
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

void release_workers(start_gate* gate, unsigned expected, int cancelled) {
    pthread_mutex_lock(&gate->mutex);
    while (!cancelled && gate->ready != expected) {
        pthread_cond_wait(&gate->condition, &gate->mutex);
    }
    gate->cancelled = cancelled;
    gate->released = 1;
    pthread_cond_broadcast(&gate->condition);
    pthread_mutex_unlock(&gate->mutex);
}

void* run_program(void* argument) {
    worker* w = (worker*)argument;
    if (w->cpu >= 0) {
        cpu_set_t affinity;
        CPU_ZERO(&affinity);
        CPU_SET(w->cpu, &affinity);
        w->error = pthread_setaffinity_np(pthread_self(), sizeof(affinity), &affinity);
    }
    if (!wait_for_start(w->gate)) {
        return nullptr;
    }
    struct bpf_test_run_opts options = {};
    options.sz = sizeof(options);
    for (unsigned iteration = 0; iteration < w->iterations && !w->error; ++iteration) {
        w->error = capsule_test_run(w->program_fd, &options);
    }
    return nullptr;
}

int run_concurrently(const int* program_fds, const int* cpus, unsigned count, unsigned iterations) {
    start_gate gate;
    pthread_t ids[kThreads];
    worker workers[kThreads] = {};
    unsigned created = 0;
    for (; created < count; ++created) {
        workers[created] = {&gate, program_fds[created], cpus ? cpus[created] : -1, iterations, 0};
        if (pthread_create(&ids[created], nullptr, run_program, &workers[created])) {
            break;
        }
    }
    release_workers(&gate, count, created != count);
    for (unsigned i = 0; i < created; ++i) {
        pthread_join(ids[i], nullptr);
    }
    int error = created != count;
    for (unsigned i = 0; i < created; ++i) {
        error |= workers[i].error != 0;
    }
    return error ? -1 : 0;
}

TEST(Atomics, NativeAndManaged) {
    CAPSULE_REQUIRE_BPF_PRIVILEGE();
    struct atomics* skeleton = atomics__open();
    ASSERT_NE(skeleton, nullptr);
    struct bpf_capsule capsule = {};
    struct bpf_capsule_config config = {};
    config.fiber_count = kThreads;
#if BPF_CAPSULE_TEST_MANAGED_RMW
    // Put one target beyond the 32 directly addressed fixed-map regions so
    // the same test executes the overflow ARRAY atomic accessors. Arena
    // profiles use the identical logical address.
    config.heap_bytes = 68ull << 20;
    config.reserved_bytes = 66ull << 20;
#else
    config.heap_bytes = 4ull << 20;
#endif
    ASSERT_EQ(bpf_capsule_configure(&capsule, skeleton->obj, config), 0) << strerror(errno);
    ASSERT_EQ(atomics__load(skeleton), 0) << strerror(errno);
    ASSERT_EQ(bpf_capsule_initialize(&capsule), 0) << strerror(errno);

    volatile struct atomic_runtime_values* values = &skeleton->data_atomrun->atomic_runtime_values;
    volatile struct atomic_managed_result* managed = &skeleton->data_atommanaged->atomic_managed_result;
    int increment_fd = bpf_program__fd(skeleton->progs.atomic_runtime_increment);

    // Native entry from four unpinned threads: every increment must land.
    int native_fds[kThreads];
    for (unsigned i = 0; i < kThreads; ++i) {
        native_fds[i] = increment_fd;
    }
    ASSERT_EQ(run_concurrently(native_fds, nullptr, kThreads, kIterations), 0);
    uint64_t increments = kThreads * kIterations;
    EXPECT_EQ(values->word, ATOMIC_RUNTIME_INITIAL_WORD + increments);
    EXPECT_EQ(values->doubleword, ATOMIC_RUNTIME_INITIAL_DOUBLEWORD + increments);

    // Managed writer/reader on two distinct CPUs. Every observed value has a
    // deterministic validity check independent of which program entered the
    // kernel first, so scheduling delay cannot fail the test.
    cpu_set_t allowed;
    int cpus[2] = {-1, -1};
    unsigned cpu_count = 0;
    ASSERT_EQ(sched_getaffinity(0, sizeof(allowed), &allowed), 0);
    for (int cpu = 0; cpu < CPU_SETSIZE && cpu_count < 2; ++cpu) {
        if (CPU_ISSET(cpu, &allowed)) {
            cpus[cpu_count++] = cpu;
        }
    }
    ASSERT_EQ(cpu_count, 2u) << "the managed tearing check needs two CPUs";
    int managed_fds[2] = {
        bpf_program__fd(skeleton->progs.atomic_managed_writer),
        bpf_program__fd(skeleton->progs.atomic_managed_reader),
    };
    ASSERT_EQ(run_concurrently(managed_fds, cpus, 2, 1), 0);
    EXPECT_EQ(managed->writer_status, (unsigned)CAPSULE_OK);
    EXPECT_EQ(managed->reader_status, (unsigned)CAPSULE_OK);
    EXPECT_EQ(managed->writer_code, 0);
    EXPECT_EQ(managed->reader_code, 0);
    EXPECT_EQ(managed->writer_failures, 0u);
    EXPECT_EQ(managed->reader_failures, 0u) << "torn managed atomic observed: 0x" << std::hex << managed->reader_failures;

#if BPF_CAPSULE_TEST_MANAGED_RMW
    ASSERT_EQ(capsule_test_run_program(skeleton->obj, "atomic_managed_rmw"), 0) << strerror(errno);
    EXPECT_EQ(managed->rmw_status, (unsigned)CAPSULE_OK);
    EXPECT_EQ(managed->rmw_code, 0);
    EXPECT_EQ(managed->rmw_failures, 0u) << "managed C atomic failure bitmap: 0x" << std::hex << managed->rmw_failures;

    int managed_increment_fds[kThreads];
    for (unsigned i = 0; i < kThreads; ++i) {
        managed_increment_fds[i] = bpf_program__fd(skeleton->progs.atomic_managed_increment);
    }
    ASSERT_EQ(run_concurrently(managed_increment_fds, nullptr, kThreads, kIterations), 0);
    ASSERT_EQ(capsule_test_run_program(skeleton->obj, "atomic_managed_counter_read"), 0) << strerror(errno);
    EXPECT_EQ(managed->counter_status, (unsigned)CAPSULE_OK);
    EXPECT_EQ(managed->counter_code, 0);
    EXPECT_EQ(managed->counter_value, (uint64_t)kThreads * kIterations);

    unsigned char* overflow = (unsigned char*)bpf_capsule_memory_start(&capsule) + (64ull << 20);
    unsigned char initial[16] = {};
    ASSERT_EQ(bpf_capsule_memcpy(&capsule, overflow, &initial, sizeof(initial)), 0) << strerror(errno);
    managed->overflow_address = (uintptr_t)overflow;
    ASSERT_EQ(capsule_test_run_program(skeleton->obj, "atomic_managed_overflow"), 0) << strerror(errno);
    EXPECT_EQ(managed->overflow_status, (unsigned)CAPSULE_OK);
    EXPECT_EQ(managed->overflow_code, 0);
    EXPECT_EQ(managed->overflow_failures, 0u) << "overflow-region C atomic failure bitmap: 0x" << std::hex << managed->overflow_failures;
#endif

    EXPECT_EQ(bpf_capsule_release(&capsule), 0) << strerror(errno);
    atomics__destroy(skeleton);
}

} // namespace
