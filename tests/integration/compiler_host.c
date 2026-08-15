// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#define _GNU_SOURCE
#include <bpf/libbpf.h>
#include <errno.h>
#include <pthread.h>
#include <sched.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include "bpf_capsule_host.h"

#include "../support/capsule_test.h"
#include "compiler_test.h"

struct allocator_start_gate {
    pthread_mutex_t mutex;
    pthread_cond_t condition;
    unsigned int ready;
    int released;
    int cancelled;
};

struct allocator_thread {
    int run_fd;
    int drain_fd;
    int cpu;
    unsigned int lane;
    volatile struct compiler_allocator_result* result;
    pthread_barrier_t* start;
    struct allocator_start_gate* gate;
    int error;
    unsigned long invocations;
    unsigned int completed;
};

static struct compiler_return_value expected_return(unsigned int seed) {
    struct compiler_return_value value = {
        .wide = 0x9e3779b97f4a7c15ull ^ seed,
        .word = 0x6a09e667u + seed * 17u,
        .half = (unsigned short)(0xbb67u ^ seed),
    };
    for (unsigned int index = 0; index < sizeof(value.bytes); ++index) {
        value.bytes[index] = (unsigned char)(seed + index * 13u);
    }
    return value;
}

static int return_equal(volatile const struct compiler_return_value* observed, const struct compiler_return_value* expected) {
    if (observed->wide != expected->wide || observed->word != expected->word || observed->half != expected->half) {
        return 0;
    }
    for (unsigned int index = 0; index < sizeof(expected->bytes); ++index) {
        if (observed->bytes[index] != expected->bytes[index]) {
            return 0;
        }
    }
    return 1;
}

static int allocator_wait_for_start(struct allocator_start_gate* gate) {
    pthread_mutex_lock(&gate->mutex);
    gate->ready++;
    // The coordinator and workers share this condition; a signal can wake a
    // different worker and strand the coordinator after both become ready.
    pthread_cond_broadcast(&gate->condition);
    while (!gate->released) {
        pthread_cond_wait(&gate->condition, &gate->mutex);
    }
    int run = !gate->cancelled;
    pthread_mutex_unlock(&gate->mutex);
    return run;
}

static void allocator_release_workers(struct allocator_start_gate* gate, int cancelled) {
    pthread_mutex_lock(&gate->mutex);
    while (!cancelled && gate->ready != 2) {
        pthread_cond_wait(&gate->condition, &gate->mutex);
    }
    gate->cancelled = cancelled;
    gate->released = 1;
    pthread_cond_broadcast(&gate->condition);
    pthread_mutex_unlock(&gate->mutex);
}

enum compiler_mode {
    MODE_ALL,
    MODE_CORE,
    MODE_FIBERS,
    MODE_ALLOCATOR,
};

static int parse_mode(const char* value, enum compiler_mode* mode) {
    if (!value) {
        *mode = MODE_ALL;
    } else if (!strcmp(value, "core")) {
        *mode = MODE_CORE;
    } else if (!strcmp(value, "fibers")) {
        *mode = MODE_FIBERS;
    } else if (!strcmp(value, "allocator")) {
        *mode = MODE_ALLOCATOR;
    } else {
        return -1;
    }
    return 0;
}

static void* run_allocator_thread(void* argument) {
    struct allocator_thread* thread = argument;
    struct bpf_test_run_opts options = {.sz = sizeof(options)};
    cpu_set_t affinity;
    CPU_ZERO(&affinity);
    CPU_SET(thread->cpu, &affinity);
    thread->error = pthread_setaffinity_np(pthread_self(), sizeof(affinity), &affinity);
    if (!allocator_wait_for_start(thread->gate) || thread->error) {
        return NULL;
    }
    for (unsigned int repetition = 0; repetition < 8; ++repetition) {
        pthread_barrier_wait(thread->start);
        if (!thread->error) {
            thread->error = capsule_test_run(thread->run_fd, &options);
            thread->invocations++;
        }
        // Hold both entry continuations before either worker can drain. This
        // proves that simultaneous computations receive distinct leases even
        // when the free pool deliberately reuses the warmest fiber first.
        pthread_barrier_wait(thread->start);
        if (thread->error) {
            continue;
        }
        while (!thread->error && thread->result->capsule[thread->lane].status == CAPSULE_PENDING) {
            if (thread->invocations >= 100000) {
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
    return NULL;
}

int main(int argc, char** argv) {
    enum compiler_mode mode;
    if ((argc != 2 && argc != 3) || parse_mode(argc == 3 ? argv[2] : NULL, &mode)) {
        fprintf(stderr, "usage: compiler_test_host OBJECT [core|fibers|allocator]\n");
        return 2;
    }
    struct bpf_object* object = bpf_object__open_file(argv[1], NULL);
    const struct bpf_capsule_config config = {
        .fiber_count = 2,
        .heap_bytes = 4ull << 20,
    };
    if (!object || bpf_capsule_configure(object, config) || capsule_test_load_object(object) || bpf_capsule_finish_initialization(object)) {
        fprintf(stderr, "cannot load compiler integration object\n");
        return 1;
    }

    size_t size = 0;
    struct bpf_map* map = bpf_object__find_map_by_name(object, ".data.ctres");
    volatile struct compiler_test_result* result = map ? bpf_map__initial_value(map, &size) : NULL;
    struct bpf_program* entry = bpf_object__find_program_by_name(object, "compiler_test_run");
    struct bpf_program* drain = bpf_object__find_program_by_name(object, "compiler_test_drain");
    struct bpf_program* native_atomic = bpf_object__find_program_by_name(object, "compiler_native_atomic_run");
    struct bpf_map* guard_map = bpf_object__find_map_by_name(object, ".data.ctguard");
    volatile struct compiler_guard_result* guards = guard_map ? bpf_map__initial_value(guard_map, &size) : NULL;
    struct bpf_program* intrinsic = bpf_object__find_program_by_name(object, "compiler_fp_intrinsic_run");
    struct bpf_program* vla = bpf_object__find_program_by_name(object, "compiler_vla_guard_run");
    struct bpf_program* exit_contract = bpf_object__find_program_by_name(object, "compiler_exit_contract_run");
    struct bpf_map* fiber_map = bpf_object__find_map_by_name(object, ".data.ctfiber");
    volatile struct compiler_fiber_result* fibers = fiber_map ? bpf_map__initial_value(fiber_map, &size) : NULL;
    struct bpf_program* fiber_start = bpf_object__find_program_by_name(object, "compiler_fiber_start");
    struct bpf_program* fiber_other = bpf_object__find_program_by_name(object, "compiler_fiber_other");
    struct bpf_program* fiber_resume = bpf_object__find_program_by_name(object, "compiler_fiber_resume");
    struct bpf_program* nested_capsule = bpf_object__find_program_by_name(object, "compiler_nested_capsule_run");
    struct bpf_map* allocator_map = bpf_object__find_map_by_name(object, ".data.ctalloc");
    volatile struct compiler_allocator_result* allocator = allocator_map ? bpf_map__initial_value(allocator_map, &size) : NULL;
    struct bpf_program* allocator_run0 = bpf_object__find_program_by_name(object, "compiler_allocator_run0");
    struct bpf_program* allocator_run1 = bpf_object__find_program_by_name(object, "compiler_allocator_run1");
    struct bpf_program* allocator_drain0 = bpf_object__find_program_by_name(object, "compiler_allocator_drain0");
    struct bpf_program* allocator_drain1 = bpf_object__find_program_by_name(object, "compiler_allocator_drain1");
    struct bpf_map* return_map = bpf_object__find_map_by_name(object, ".data.ctreturn");
    volatile struct compiler_return_result* returns = return_map ? bpf_map__initial_value(return_map, &size) : NULL;
    struct bpf_program* return_immediate = bpf_object__find_program_by_name(object, "compiler_return_immediate_run");
    struct bpf_program* return_suspended = bpf_object__find_program_by_name(object, "compiler_return_suspended_run");
    struct bpf_program* return_drain = bpf_object__find_program_by_name(object, "compiler_return_suspended_drain");
    if (!result || !entry || !drain || !native_atomic || !guards || !intrinsic || !vla || !exit_contract || !fibers || !fiber_start || !fiber_other ||
        !fiber_resume || !nested_capsule || !allocator || !allocator_run0 || !allocator_run1 || !allocator_drain0 || !allocator_drain1 || !returns ||
        !return_immediate || !return_suspended || !return_drain) {
        fprintf(stderr, "compiler integration object is incomplete\n");
        return 1;
    }

    struct bpf_test_run_opts options = {.sz = sizeof(options)};
    int error = 0;
    int pass = 1;
    if (mode == MODE_ALL || mode == MODE_CORE) {
        error = capsule_test_run(bpf_program__fd(nested_capsule), &options);
        if (error || options.retval) {
            fprintf(stderr, "nested capsule_call failed: syscall=%d retval=%u errno=%d\n", error, options.retval, errno);
            pass = 0;
        }
        unsigned long entries = 1;
        unsigned long drains = 0;
        error = capsule_test_run(bpf_program__fd(entry), &options);
        while (!error && result->pending && !result->code) {
            if (drains >= 1000000) {
                fprintf(stderr, "compiler integration exceeded drain cap\n");
                error = -1;
                break;
            }
            error = capsule_test_run(bpf_program__fd(drain), &options);
            drains++;
        }
        fprintf(stderr, "invocations: %lu entries + %lu drains\n", entries, drains);
        fprintf(
            stderr,
            "failures=%llu checksum=%016llx pending=%llu code=%lld sparse-diff=%lld init-diff=%lld copy-failures=%llu first-copy-failure=%llu "
            "memset-failures=%llu first-memset-failure=%llu parallel-phi-sum=%llu\n",
            result->failures, result->checksum, result->pending, (long long)result->code, result->sparse_pointer_difference,
            result->initialized_pointer_difference, result->copy_failures, result->first_copy_failure, result->memset_failures, result->first_memset_failure,
            result->parallel_phi_sum
        );
        pass = !error && !result->failures && result->checksum == 0x9c4e7252bfb60f08ull && !result->pending && !result->code;
        if (error) {
            fprintf(stderr, "test run failed: syscall=%d retval=%d errno=%d\n", error, (int)options.retval, errno);
        }

        if (pass) {
            error = capsule_test_run(bpf_program__fd(native_atomic), &options);
            pass = !error && result->native_atomic_failures == 0;
            if (!pass) {
                fprintf(stderr, "native atomic ISA failed: error=%d failures=%llx\n", error, result->native_atomic_failures);
            }
        }

        if (pass) {
            error = capsule_test_run(bpf_program__fd(intrinsic), &options);
            pass = !error && guards->intrinsic_status == CAPSULE_EXITED && guards->intrinsic_code == CAPSULE_ERROR_UNSUPPORTED_FP_INTRINSIC &&
                guards->intrinsic_after == 1 && guards->intrinsic_value == 0;
            if (!pass) {
                fprintf(
                    stderr, "intrinsic guard failed: status=%llu code=%lld after=%llu value=%llu\n", guards->intrinsic_status,
                    (long long)guards->intrinsic_code, guards->intrinsic_after, guards->intrinsic_value
                );
            }
        }
        if (pass) {
            error = capsule_test_run(bpf_program__fd(vla), &options);
            pass = !error && guards->vla_before == 1 && guards->vla_after == 0;
            if (!pass) {
                fprintf(stderr, "VLA guard failed: before=%llu after=%llu\n", guards->vla_before, guards->vla_after);
            }
        }
        if (pass) {
            error = capsule_test_run(bpf_program__fd(exit_contract), &options);
            // The guest calls capsule_exit(-37); the 0xff exit-status mask
            // makes the caller observe 219, never a framework negative.
            pass = !error && guards->exit_held_status == CAPSULE_PENDING && guards->exit_status == CAPSULE_EXITED && guards->exit_code == 219 &&
                guards->exit_after == 0 && guards->exit_reuse_status == CAPSULE_OK && guards->exit_reset_status == CAPSULE_OK;
            if (!pass) {
                fprintf(
                    stderr, "exit contract failed: error=%d held=%u exited=%u code=%lld after=%u reuse=%u reset=%u\n", error, guards->exit_held_status,
                    guards->exit_status, (long long)guards->exit_code, guards->exit_after, guards->exit_reuse_status, guards->exit_reset_status
                );
            }
        }
        if (pass) {
            error = capsule_test_run(bpf_program__fd(return_immediate), &options);
            struct compiler_return_value expected = expected_return(0x1234u);
            pass = !error && returns->immediate_capsule.status == CAPSULE_OK && !returns->immediate_capsule.code && !returns->immediate_capsule.reserved &&
                return_equal(&returns->immediate, &expected);
            if (!pass) {
                fprintf(
                    stderr, "immediate aggregate return failed: error=%d status=%u capsule-code=%lld value=%llx/%x/%x\n", error,
                    returns->immediate_capsule.status, (long long)returns->immediate_capsule.code, returns->immediate.wide, returns->immediate.word,
                    returns->immediate.half
                );
            }
        }
        if (pass) {
            error = capsule_test_run(bpf_program__fd(return_suspended), &options);
            unsigned int return_drains = 0;
            int began_pending =
                !error && returns->suspended_capsule.status == CAPSULE_PENDING && !returns->suspended_capsule.reserved && returns->pending_output_unchanged;
            while (!error && returns->suspended_capsule.status == CAPSULE_PENDING && return_drains++ < 10000) {
                error = capsule_test_run(bpf_program__fd(return_drain), &options);
            }
            unsigned int seed = 0x5678u;
            for (unsigned int index = 0; index < 512; ++index) {
                seed = seed * 33u + 17u;
            }
            struct compiler_return_value expected = expected_return(seed);
            pass = began_pending && !error && return_drains < 10000 && returns->suspended_capsule.status == CAPSULE_OK && !returns->suspended_capsule.code &&
                !returns->suspended_capsule.reserved && return_equal(&returns->suspended, &expected);
            if (!pass) {
                fprintf(
                    stderr,
                    "suspended aggregate return failed: began-pending=%d unchanged=%u drains=%u error=%d status=%u capsule-code=%lld "
                    "value=%llx/%x/%x\n",
                    began_pending, returns->pending_output_unchanged, return_drains, error, returns->suspended_capsule.status,
                    (long long)returns->suspended_capsule.code, returns->suspended.wide, returns->suspended.word, returns->suspended.half
                );
            }
        }
    }
    if (pass && (mode == MODE_ALL || mode == MODE_FIBERS)) {
        error = capsule_test_run(bpf_program__fd(fiber_start), &options);
        unsigned int fiber_drains = 0;
        while (!error && fibers->other_status == CAPSULE_PENDING && fiber_drains++ < 10000) {
            error = capsule_test_run(bpf_program__fd(fiber_other), &options);
        }
        while (!error && fibers->resume_status == CAPSULE_PENDING && fiber_drains++ < 10000) {
            error = capsule_test_run(bpf_program__fd(fiber_resume), &options);
        }
        pass = !error && fiber_drains < 10000 && fibers->start_status == CAPSULE_PENDING && fibers->second_start_status == CAPSULE_PENDING &&
            fibers->other_status == CAPSULE_OK && fibers->resume_status == CAPSULE_OK && fibers->exhausted_status == CAPSULE_EXITED &&
            fibers->first_fiber != fibers->second_fiber && fibers->reset_status == CAPSULE_OK && fibers->after_reset_status == CAPSULE_OK &&
            fibers->reset_fiber != BPF_CAPSULE_NO_CONTINUATION && fibers->after_reset_fiber < 2 && fibers->paused_pending != 0 && fibers->paused_code == 0 &&
            fibers->other_value == 0xa5 && fibers->resumed_value == 0x5a;
        if (!pass) {
            fprintf(
                stderr,
                "fiber isolation failed: start=%u/%u continue=%u/%lld,%u/%lld "
                "exhausted=%u token=%llu/%llu reset=%u/%llu after=%u/%u pending=%llu "
                "code=%lld value=%llx/%llx\n",
                fibers->start_status, fibers->second_start_status, fibers->other_status, (long long)fibers->other_code, fibers->resume_status,
                (long long)fibers->resume_code, fibers->exhausted_status, (unsigned long long)fibers->first_fiber, (unsigned long long)fibers->second_fiber,
                fibers->reset_status, (unsigned long long)fibers->reset_fiber, fibers->after_reset_status, fibers->after_reset_fiber, fibers->paused_pending,
                (long long)fibers->paused_code, fibers->other_value, fibers->resumed_value
            );
        }
    }
    if (pass && (mode == MODE_ALL || mode == MODE_ALLOCATOR)) {
        cpu_set_t allowed;
        int cpus[2] = {-1, -1};
        unsigned int cpu_count = 0;
        if (!sched_getaffinity(0, sizeof(allowed), &allowed)) {
            for (int cpu = 0; cpu < CPU_SETSIZE && cpu_count < 2; ++cpu) {
                if (CPU_ISSET(cpu, &allowed)) {
                    cpus[cpu_count++] = cpu;
                }
            }
        }
        pthread_barrier_t start;
        struct allocator_start_gate gate = {0};
        int barrier_ready = cpu_count == 2 && !pthread_barrier_init(&start, NULL, 2);
        int mutex_ready = barrier_ready && !pthread_mutex_init(&gate.mutex, NULL);
        int condition_ready = mutex_ready && !pthread_cond_init(&gate.condition, NULL);
        int setup_error = !condition_ready;
        if (setup_error) {
            fprintf(stderr, "cannot initialize allocator worker gate\n");
            pass = 0;
        }
        struct allocator_thread threads[2] = {
            {
                .run_fd = bpf_program__fd(allocator_run0),
                .drain_fd = bpf_program__fd(allocator_drain0),
                .cpu = cpus[0],
                .lane = 0,
                .result = allocator,
                .start = &start,
                .gate = &gate,
            },
            {
                .run_fd = bpf_program__fd(allocator_run1),
                .drain_fd = bpf_program__fd(allocator_drain1),
                .cpu = cpus[1],
                .lane = 1,
                .result = allocator,
                .start = &start,
                .gate = &gate,
            },
        };
        pthread_t ids[2];
        struct timespec begin, end;
        clock_gettime(CLOCK_MONOTONIC, &begin);
        int create0 = setup_error ? setup_error : pthread_create(&ids[0], NULL, run_allocator_thread, &threads[0]);
        int create1 = setup_error ? setup_error : pthread_create(&ids[1], NULL, run_allocator_thread, &threads[1]);
        if (!setup_error) {
            allocator_release_workers(&gate, create0 || create1);
        }
        if (!create0) {
            pthread_join(ids[0], NULL);
        }
        if (!create1) {
            pthread_join(ids[1], NULL);
        }
        clock_gettime(CLOCK_MONOTONIC, &end);
        if (condition_ready) {
            pthread_cond_destroy(&gate.condition);
        }
        if (mutex_ready) {
            pthread_mutex_destroy(&gate.mutex);
        }
        if (barrier_ready) {
            pthread_barrier_destroy(&start);
        }
        double milliseconds = (end.tv_sec - begin.tv_sec) * 1e3 + (end.tv_nsec - begin.tv_nsec) / 1e6;
        pass = !create0 && !create1 && !threads[0].error && !threads[1].error && !allocator->failures[0] && !allocator->failures[1] &&
            allocator->first_fiber[0] != BPF_CAPSULE_NO_CONTINUATION && allocator->first_fiber[1] != BPF_CAPSULE_NO_CONTINUATION &&
            allocator->first_fiber[0] != allocator->first_fiber[1] && threads[0].completed == 8 && threads[1].completed == 8 &&
            allocator->operations[0] == 624 && allocator->operations[1] == 624;
        fprintf(
            stderr,
            "allocator concurrency: %.2f ms, runs=%u/%u "
            "invocations=%lu/%lu continuations=%llu/%llu "
            "operations=%llu/%llu failures=%llx/%llx\n",
            milliseconds, threads[0].completed, threads[1].completed, threads[0].invocations, threads[1].invocations,
            (unsigned long long)allocator->first_fiber[0], (unsigned long long)allocator->first_fiber[1], allocator->operations[0], allocator->operations[1],
            allocator->failures[0], allocator->failures[1]
        );
        if (!pass) {
            fprintf(
                stderr,
                "allocator capsules: status=%u/%u code=%lld/%lld "
                "thread-error=%d/%d\n",
                allocator->capsule[0].status, allocator->capsule[1].status, (long long)allocator->capsule[0].code, (long long)allocator->capsule[1].code,
                threads[0].error, threads[1].error
            );
        }
    }
    const char* success = mode == MODE_CORE ? "COMPILER-CORE-PASS\n"
        : mode == MODE_FIBERS               ? "FIBER-PASS\n"
        : mode == MODE_ALLOCATOR            ? "ALLOCATOR-CONCURRENCY-PASS\n"
                                            : "COMPILER-PASS\n";
    const char* failure = mode == MODE_CORE ? "COMPILER-CORE-FAIL\n"
        : mode == MODE_FIBERS               ? "FIBER-FAIL\n"
        : mode == MODE_ALLOCATOR            ? "ALLOCATOR-CONCURRENCY-FAIL\n"
                                            : "COMPILER-FAIL\n";
    printf("%s", pass ? success : failure);
    bpf_object__close(object);
    return pass ? 0 : 1;
}
