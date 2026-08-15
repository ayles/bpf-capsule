// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#define _GNU_SOURCE
#include <bpf/libbpf.h>
#include <pthread.h>
#include <sched.h>
#include <stdio.h>

#include "bpf_capsule_host.h"

#include "../support/capsule_test.h"
#include "native.h"

#define ATOMIC_RUNTIME_THREADS 4u
#define ATOMIC_RUNTIME_ITERATIONS 256u

struct atomic_start_gate {
    pthread_mutex_t mutex;
    pthread_cond_t condition;
    unsigned int ready;
    int released;
    int cancelled;
};

struct atomic_worker {
    struct atomic_start_gate* gate;
    int program_fd;
    int cpu;
    unsigned int iterations;
    int error;
};

static int wait_for_start(struct atomic_start_gate* gate) {
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

static void release_workers(struct atomic_start_gate* gate, unsigned int expected, int cancelled) {
    pthread_mutex_lock(&gate->mutex);
    while (!cancelled && gate->ready != expected) {
        pthread_cond_wait(&gate->condition, &gate->mutex);
    }
    gate->cancelled = cancelled;
    gate->released = 1;
    pthread_cond_broadcast(&gate->condition);
    pthread_mutex_unlock(&gate->mutex);
}

static void* run_program(void* argument) {
    struct atomic_worker* worker = argument;
    if (worker->cpu >= 0) {
        cpu_set_t affinity;
        CPU_ZERO(&affinity);
        CPU_SET(worker->cpu, &affinity);
        worker->error = pthread_setaffinity_np(pthread_self(), sizeof(affinity), &affinity);
    }
    if (!wait_for_start(worker->gate)) {
        return NULL;
    }
    struct bpf_test_run_opts options = {.sz = sizeof(options)};
    for (unsigned int iteration = 0; iteration < worker->iterations && !worker->error; ++iteration) {
        worker->error = capsule_test_run(worker->program_fd, &options);
    }
    return NULL;
}

static int run_concurrently(const int* program_fds, const int* cpus, unsigned int count, unsigned int iterations) {
    if (!count || count > ATOMIC_RUNTIME_THREADS) {
        return -1;
    }
    struct atomic_start_gate gate = {0};
    int mutex_ready = !pthread_mutex_init(&gate.mutex, NULL);
    int condition_ready = mutex_ready && !pthread_cond_init(&gate.condition, NULL);
    if (!condition_ready) {
        if (mutex_ready) {
            pthread_mutex_destroy(&gate.mutex);
        }
        return -1;
    }

    pthread_t ids[ATOMIC_RUNTIME_THREADS];
    struct atomic_worker workers[ATOMIC_RUNTIME_THREADS] = {0};
    unsigned int created = 0;
    for (; created < count; ++created) {
        workers[created].gate = &gate;
        workers[created].program_fd = program_fds[created];
        workers[created].cpu = cpus ? cpus[created] : -1;
        workers[created].iterations = iterations;
        if (pthread_create(&ids[created], NULL, run_program, &workers[created])) {
            break;
        }
    }
    release_workers(&gate, count, created != count);
    for (unsigned int worker = 0; worker < created; ++worker) {
        pthread_join(ids[worker], NULL);
    }

    int error = created != count;
    for (unsigned int worker = 0; worker < created; ++worker) {
        error |= workers[worker].error != 0;
    }
    pthread_cond_destroy(&gate.condition);
    pthread_mutex_destroy(&gate.mutex);
    return error ? -1 : 0;
}

int main(int argc, char** argv) {
    if (argc != 2) {
        fprintf(stderr, "usage: atomic_runtime_host OBJECT\n");
        return 2;
    }
    struct bpf_object* object = bpf_object__open_file(argv[1], NULL);
    const struct bpf_capsule_config config = {
        .fiber_count = 2,
        .heap_bytes = 4ull << 20,
    };
    if (!object || bpf_capsule_configure(object, config) || capsule_test_load_object(object) || bpf_capsule_finish_initialization(object)) {
        fprintf(stderr, "cannot load native atomic object\n");
        return 1;
    }

    size_t values_size = 0;
    struct bpf_map* map = bpf_object__find_map_by_name(object, ".data.atomrun");
    volatile struct atomic_runtime_values* values = map ? bpf_map__initial_value(map, &values_size) : NULL;
    struct bpf_program* program = bpf_object__find_program_by_name(object, "atomic_runtime_increment");
    struct bpf_map* managed_map = bpf_object__find_map_by_name(object, ".data.atommanaged");
    size_t managed_size = 0;
    volatile struct atomic_managed_result* managed = managed_map ? bpf_map__initial_value(managed_map, &managed_size) : NULL;
    struct bpf_program* managed_writer = bpf_object__find_program_by_name(object, "atomic_managed_writer");
    struct bpf_program* managed_reader = bpf_object__find_program_by_name(object, "atomic_managed_reader");
    int pass = values && values_size >= sizeof(*values) && managed && managed_size >= sizeof(*managed) && program && managed_writer && managed_reader;

    int native_fds[ATOMIC_RUNTIME_THREADS];
    for (unsigned int worker = 0; worker < ATOMIC_RUNTIME_THREADS; ++worker) {
        native_fds[worker] = program ? bpf_program__fd(program) : -1;
    }
    if (pass) {
        pass = !run_concurrently(native_fds, NULL, ATOMIC_RUNTIME_THREADS, ATOMIC_RUNTIME_ITERATIONS);
    }

    uint64_t increments = ATOMIC_RUNTIME_THREADS * ATOMIC_RUNTIME_ITERATIONS;
    pass = pass && values->word == ATOMIC_RUNTIME_INITIAL_WORD + increments && values->doubleword == ATOMIC_RUNTIME_INITIAL_DOUBLEWORD + increments;
    if (!pass && values) {
        fprintf(stderr, "atomic totals=%u/%llu expected=%llu increments\n", values->word, values->doubleword, increments);
    }

    cpu_set_t allowed;
    int managed_cpus[2] = {-1, -1};
    unsigned int cpu_count = 0;
    if (pass && !sched_getaffinity(0, sizeof(allowed), &allowed)) {
        for (int cpu = 0; cpu < CPU_SETSIZE && cpu_count < 2; ++cpu) {
            if (CPU_ISSET(cpu, &allowed)) {
                managed_cpus[cpu_count++] = cpu;
            }
        }
    }
    int managed_fds[2] = {
        managed_writer ? bpf_program__fd(managed_writer) : -1,
        managed_reader ? bpf_program__fd(managed_reader) : -1,
    };
    if (pass) {
        // Release both test-run syscalls together and pin them to distinct
        // CPUs, but do not make a finite BPF-side spin rendezvous part of the
        // result. The scheduler may delay either syscall for longer than any
        // verifier-bounded wait; that tests timing, not atomic load/store
        // correctness. The long writer/reader bodies below are the concurrent
        // stress, while every observed value has a deterministic validity
        // check independent of which program entered the kernel first.
        pass = cpu_count == 2 && !run_concurrently(managed_fds, managed_cpus, 2, 1) && managed->writer_status == CAPSULE_OK &&
            managed->reader_status == CAPSULE_OK && managed->writer_code == 0 && managed->reader_code == 0 && managed->writer_failures == 0 &&
            managed->reader_failures == 0;
    }
    if (!pass && managed) {
        fprintf(
            stderr, "managed atomics: status=%u/%u code=%lld/%lld failures=%llx/%llx\n", managed->writer_status, managed->reader_status,
            (long long)managed->writer_code, (long long)managed->reader_code, managed->writer_failures, managed->reader_failures
        );
    }
    printf("%s", pass ? "ATOMIC-RUNTIME-PASS\n" : "ATOMIC-RUNTIME-FAIL\n");
    bpf_object__close(object);
    return pass ? 0 : 1;
}
