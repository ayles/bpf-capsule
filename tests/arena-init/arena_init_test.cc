// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
// Arena initialization contract: bpf_capsule_initialize() is mandatory and
// is the only place allocation happens. Initialized objects serve eight
// simultaneous lanes with no retries; an uninitialized object fails every
// entry closed with -EAGAIN (no lazy fallback) and starts serving once the
// initializer has run. Every lane's write must land at the fixed-up
// pointer.
#include "capsule_gtest.h"

#include "bpf_capsule_host.h"
#include "arena_init.skel.h"

#include <pthread.h>

namespace {

constexpr int kLanes = 8;

struct start_gate {
    pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
    pthread_cond_t condition = PTHREAD_COND_INITIALIZER;
    unsigned ready = 0;
    int released = 0;
    int cancelled = 0;
};

struct lane_run {
    int fd;
    start_gate* gate;
    int error;
    int retval;
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

void* run_lane(void* argument) {
    lane_run* lane = (lane_run*)argument;
    struct bpf_test_run_opts options = {};
    options.sz = sizeof(options);
    if (!wait_for_start(lane->gate)) {
        return nullptr;
    }
    lane->error = bpf_prog_test_run_opts(lane->fd, &options);
    lane->retval = (int)options.retval;
    return nullptr;
}

void exercise(bool eager, unsigned* retries) {
    struct arena_init* skeleton = arena_init__open();
    ASSERT_NE(skeleton, nullptr);
    struct bpf_capsule capsule = {};
    struct bpf_capsule_config config = {};
    config.fiber_count = kLanes;
    config.heap_bytes = 4ull << 20;
    ASSERT_EQ(bpf_capsule_configure(&capsule, skeleton->obj, config), 0) << strerror(errno);
    ASSERT_EQ(arena_init__load(skeleton), 0) << strerror(errno);
    if (eager) {
        ASSERT_EQ(bpf_capsule_initialize(&capsule), 0) << strerror(errno);
    }

    start_gate gate;
    lane_run lanes[kLanes] = {};
    pthread_t threads[kLanes];
    int created = 0;
    for (int lane = 0; lane < kLanes; ++lane) {
        char name[32];
        snprintf(name, sizeof(name), "arena_init_lane%d", lane);
        struct bpf_program* program = bpf_object__find_program_by_name(skeleton->obj, name);
        if (!program) {
            break;
        }
        lanes[lane].fd = bpf_program__fd(program);
        lanes[lane].gate = &gate;
        if (pthread_create(&threads[lane], nullptr, run_lane, &lanes[lane])) {
            break;
        }
        created++;
    }
    release_workers(&gate, kLanes, created != kLanes);
    for (int lane = 0; lane < created; ++lane) {
        pthread_join(threads[lane], nullptr);
    }
    ASSERT_EQ(created, kLanes);

    for (int lane = 0; lane < kLanes; ++lane) {
        ASSERT_EQ(lanes[lane].error, 0) << "lane " << lane << " syscall failed";
        if (eager) {
            ASSERT_EQ(lanes[lane].retval, 0) << "lane " << lane << " returned " << lanes[lane].retval << " on an initialized object";
        } else {
            // Fail closed: nothing initializes lazily.
            ASSERT_EQ(lanes[lane].retval, -EAGAIN) << "lane " << lane << " ran against an uninitialized object";
            (*retries)++;
        }
    }
    if (!eager) {
        // The mandatory verb unblocks the same entries.
        ASSERT_EQ(bpf_capsule_initialize(&capsule), 0) << strerror(errno);
        for (int lane = 0; lane < kLanes; ++lane) {
            struct bpf_test_run_opts options = {};
            options.sz = sizeof(options);
            ASSERT_EQ(capsule_test_run(lanes[lane].fd, &options), 0) << "lane " << lane << " post-initialize run failed";
        }
    }

    ASSERT_EQ(capsule_test_run_program(skeleton->obj, "arena_init_verify"), 0) << strerror(errno);
    EXPECT_EQ(skeleton->data_ainit->arena_init_mask, 0xffu) << "every lane's write landed at the fixed-up pointer";
    EXPECT_EQ(bpf_capsule_release(&capsule), 0) << strerror(errno);
    arena_init__destroy(skeleton);
}

TEST(ArenaInit, EagerInitializationNeedsNoRetries) {
    CAPSULE_REQUIRE_BPF_PRIVILEGE();
    unsigned retries = 0;
    exercise(true, &retries);
    EXPECT_EQ(retries, 0u);
}

TEST(ArenaInit, UninitializedEntriesFailClosed) {
    CAPSULE_REQUIRE_BPF_PRIVILEGE();
    unsigned refused = 0;
    exercise(false, &refused);
    EXPECT_EQ(refused, (unsigned)kLanes);
}

} // namespace
