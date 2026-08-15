// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#define _GNU_SOURCE
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <pthread.h>
#include <sched.h>
#include <stdio.h>

#include "bpf_capsule_host.h"

#include "../support/capsule_test.h"

#define HOST_ITERATIONS 64u
#define WORKERS 2u
struct start_gate {
    pthread_mutex_t mutex;
    pthread_cond_t condition;
    unsigned int ready;
    int released;
    int cancelled;
};

struct worker {
    struct start_gate* gate;
    int program_fd;
    int cpu;
    int error;
};

static int wait_for_start(struct start_gate* gate) {
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

static void release_workers(struct start_gate* gate, unsigned int expected, int cancelled) {
    pthread_mutex_lock(&gate->mutex);
    while (!cancelled && gate->ready != expected) {
        pthread_cond_wait(&gate->condition, &gate->mutex);
    }
    gate->cancelled = cancelled;
    gate->released = 1;
    pthread_cond_broadcast(&gate->condition);
    pthread_mutex_unlock(&gate->mutex);
}

static void* run_worker(void* argument) {
    struct worker* worker = argument;
    cpu_set_t affinity;
    CPU_ZERO(&affinity);
    CPU_SET(worker->cpu, &affinity);
    worker->error = pthread_setaffinity_np(pthread_self(), sizeof(affinity), &affinity);
    if (!wait_for_start(worker->gate) || worker->error) {
        return NULL;
    }

    struct bpf_test_run_opts options = {.sz = sizeof(options)};
    for (unsigned int iteration = 0; iteration < HOST_ITERATIONS && !worker->error; ++iteration) {
        worker->error = capsule_test_run(worker->program_fd, &options);
    }
    return NULL;
}

int main(int argc, char** argv) {
    if (argc != 2) {
        fprintf(stderr, "usage: physical_spill_host OBJECT\n");
        return 2;
    }

    cpu_set_t allowed;
    int cpus[WORKERS] = {-1, -1};
    int pass = !sched_getaffinity(0, sizeof(allowed), &allowed);
    unsigned int found = 0;
    for (int cpu = 0; pass && cpu < CPU_SETSIZE && found < WORKERS; ++cpu) {
        if (CPU_ISSET(cpu, &allowed)) {
            cpus[found++] = cpu;
        }
    }
    if (found != WORKERS) {
        fprintf(stderr, "physical spill concurrency requires two CPUs\n");
        return 1;
    }

    struct bpf_object* object = bpf_object__open_file(argv[1], NULL);
    if (!object || capsule_test_load_object(object) || bpf_capsule_finish_initialization(object)) {
        fprintf(stderr, "cannot load physical-spill object\n");
        return 1;
    }
    struct bpf_program* programs[WORKERS] = {
        bpf_object__find_program_by_name(object, "spill_fiber_zero"),
        bpf_object__find_program_by_name(object, "spill_fiber_two"),
    };
    struct bpf_program* overflow_program = bpf_object__find_program_by_name(object, "spill_overflow");
    struct bpf_map* map = bpf_object__find_map_by_name(object, ".bss.spillr");
    pass = pass && programs[0] && programs[1] && overflow_program && map && bpf_map__value_size(map) >= 6 * sizeof(uint64_t);

    struct bpf_test_run_opts overflow_options = {.sz = sizeof(overflow_options)};
    pass = pass && !capsule_test_run(bpf_program__fd(overflow_program), &overflow_options);

    struct start_gate gate = {0};
    int mutex_ready = pass && !pthread_mutex_init(&gate.mutex, NULL);
    int condition_ready = mutex_ready && !pthread_cond_init(&gate.condition, NULL);
    pass = pass && condition_ready;
    pthread_t threads[WORKERS];
    struct worker workers[WORKERS] = {0};
    unsigned int created = 0;
    if (pass) {
        for (; created < WORKERS; ++created) {
            workers[created].gate = &gate;
            workers[created].program_fd = bpf_program__fd(programs[created]);
            workers[created].cpu = cpus[created];
            if (pthread_create(&threads[created], NULL, run_worker, &workers[created])) {
                break;
            }
        }
        release_workers(&gate, WORKERS, created != WORKERS);
        for (unsigned int worker = 0; worker < created; ++worker) {
            pthread_join(threads[worker], NULL);
        }
        pass = pass && created == WORKERS;
        for (unsigned int worker = 0; worker < created; ++worker) {
            pass = pass && !workers[worker].error;
        }
    }

    unsigned int key = 0;
    uint64_t results[6] = {0};
    int lookup_error = map ? bpf_map_lookup_elem(bpf_map__fd(map), &key, results) : -1;
    pass = pass && !lookup_error;
    // The overflow probe copies the fiber's whole encoded exit word: the
    // CAPSULE_EXITED tag in the low half, the signed framework code in the
    // high half (little-endian).
    uint64_t overflow_word = ((uint64_t)(int64_t)CAPSULE_ERROR_STACK_OVERFLOW << 32) | CAPSULE_EXITED;
    if (!lookup_error) {
        pass = pass && results[0] == 0 && results[1] == 0 && results[2] == HOST_ITERATIONS && results[3] == HOST_ITERATIONS && results[4] == overflow_word &&
            results[5] == 0;
        if (!pass) {
            fprintf(
                stderr,
                "physical spill results: errors=%llu/%llu calls=%llu/%llu "
                "overflow=%#llx return=%llu\n",
                results[0], results[1], results[2], results[3], results[4], results[5]
            );
        }
    }
    printf("%s", pass ? "PHYSICAL-SPILL-PASS\n" : "PHYSICAL-SPILL-FAIL\n");

    if (condition_ready) {
        pthread_cond_destroy(&gate.condition);
    }
    if (mutex_ready) {
        pthread_mutex_destroy(&gate.mutex);
    }
    bpf_object__close(object);
    return pass ? 0 : 1;
}
