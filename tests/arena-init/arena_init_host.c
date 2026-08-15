// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#include <bpf/libbpf.h>
#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>

#include "bpf_capsule_host.h"

#include "../support/capsule_test.h"

#define ARENA_INIT_LANES 8

struct start_gate {
    pthread_mutex_t mutex;
    pthread_cond_t condition;
    unsigned int ready;
    int released;
    int cancelled;
};

struct lane_run {
    int fd;
    struct start_gate* gate;
    int error;
    int retval;
};

static int wait_for_start(struct start_gate* gate) {
    pthread_mutex_lock(&gate->mutex);
    gate->ready++;
    // Workers and the coordinator wait on the same condition. Wake all of
    // them so readiness cannot be consumed by another unreleased worker.
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

static void* run_lane(void* argument) {
    struct lane_run* lane = argument;
    struct bpf_test_run_opts options = {.sz = sizeof(options)};
    if (!wait_for_start(lane->gate)) {
        return NULL;
    }
    lane->error = bpf_prog_test_run_opts(lane->fd, &options);
    lane->retval = (int)options.retval;
    return NULL;
}

static int run_checked(int fd) {
    struct bpf_test_run_opts options = {.sz = sizeof(options)};
    int error = bpf_prog_test_run_opts(fd, &options);
    if (!error && (int)options.retval < 0) {
        errno = -(int)options.retval;
        return -1;
    }
    return error;
}

static int exercise(const char* path, int eager, unsigned int* retries) {
    struct bpf_object* object = bpf_object__open_file(path, NULL);
    const struct bpf_capsule_config config = {
        .fiber_count = ARENA_INIT_LANES,
        .heap_bytes = 4ull << 20,
    };
    int error = !object || bpf_capsule_configure(object, config) ? -1
        : eager                                                  ? capsule_test_load_object(object) || bpf_capsule_finish_initialization(object)
                                                                 : bpf_object__load(object);
    if (error) {
        fprintf(stderr, "%s arena object did not load\n", eager ? "eager" : "fallback");
        if (object) {
            bpf_object__close(object);
        }
        return -1;
    }

    struct start_gate gate = {0};
    if (pthread_mutex_init(&gate.mutex, NULL) || pthread_cond_init(&gate.condition, NULL)) {
        fprintf(stderr, "cannot initialize arena worker gate\n");
        bpf_object__close(object);
        return -1;
    }
    struct lane_run lanes[ARENA_INIT_LANES] = {0};
    pthread_t threads[ARENA_INIT_LANES];
    int created = 0;
    for (int lane = 0; lane < ARENA_INIT_LANES; ++lane) {
        char name[32];
        snprintf(name, sizeof(name), "arena_init_lane%d", lane);
        struct bpf_program* program = bpf_object__find_program_by_name(object, name);
        if (!program) {
            break;
        }
        lanes[lane].fd = bpf_program__fd(program);
        lanes[lane].gate = &gate;
        if (pthread_create(&threads[lane], NULL, run_lane, &lanes[lane])) {
            break;
        }
        created++;
    }
    release_workers(&gate, ARENA_INIT_LANES, created != ARENA_INIT_LANES);
    for (int lane = 0; lane < created; ++lane) {
        pthread_join(threads[lane], NULL);
    }
    pthread_cond_destroy(&gate.condition);
    pthread_mutex_destroy(&gate.mutex);
    if (created != ARENA_INIT_LANES) {
        fprintf(stderr, "could not start every arena lane\n");
        bpf_object__close(object);
        return -1;
    }

    for (int lane = 0; lane < ARENA_INIT_LANES; ++lane) {
        if (lanes[lane].error) {
            fprintf(stderr, "arena lane %d syscall failed: %d\n", lane, lanes[lane].error);
            bpf_object__close(object);
            return -1;
        }
        if (lanes[lane].retval == -EAGAIN && !eager) {
            if (run_checked(lanes[lane].fd)) {
                fprintf(stderr, "arena lane %d retry failed\n", lane);
                bpf_object__close(object);
                return -1;
            }
            (*retries)++;
        } else if (lanes[lane].retval) {
            fprintf(stderr, "arena lane %d returned %d in %s mode\n", lane, lanes[lane].retval, eager ? "eager" : "fallback");
            bpf_object__close(object);
            return -1;
        }
    }

    struct bpf_program* verify = bpf_object__find_program_by_name(object, "arena_init_verify");
    struct bpf_map* result_map = bpf_object__find_map_by_name(object, ".data.ainit");
    size_t size = 0;
    volatile unsigned int* mask = result_map ? bpf_map__initial_value(result_map, &size) : NULL;
    int pass = verify && mask && size >= sizeof(*mask) && !run_checked(bpf_program__fd(verify)) && *mask == 0xffu;
    if (!pass) {
        fprintf(stderr, "%s arena mask=%x\n", eager ? "eager" : "fallback", mask ? *mask : 0);
    }
    bpf_object__close(object);
    return pass ? 0 : -1;
}

int main(int argc, char** argv) {
    if (argc != 2) {
        fprintf(stderr, "usage: arena_init_host OBJECT\n");
        return 2;
    }
    unsigned int eager_retries = 0;
    unsigned int fallback_retries = 0;
    int pass = !exercise(argv[1], 1, &eager_retries) && !exercise(argv[1], 0, &fallback_retries) && eager_retries == 0;
    fprintf(stderr, "arena initialization retries: eager=%u fallback=%u\n", eager_retries, fallback_retries);
    printf(pass ? "ARENA-INIT-PASS\n" : "ARENA-INIT-FAIL\n");
    return pass ? 0 : 1;
}
