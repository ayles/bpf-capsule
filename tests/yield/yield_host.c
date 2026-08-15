// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#include <bpf/libbpf.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include "bpf_capsule_host.h"

#include "../support/capsule_test.h"
#include "yield_test.h"

static int run(struct bpf_object* object, const char* name) {
    struct bpf_program* program = bpf_object__find_program_by_name(object, name);
    struct bpf_test_run_opts options = {.sz = sizeof(options)};
    return program ? capsule_test_run(bpf_program__fd(program), &options) : -1;
}

static uint64_t monotonic_ns(void) {
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC_RAW, &now);
    return (uint64_t)now.tv_sec * 1000000000ull + now.tv_nsec;
}

static int measure(struct bpf_object* object, const char* name, unsigned int repeat, uint64_t* duration) {
    struct bpf_program* program = bpf_object__find_program_by_name(object, name);
    if (!program) {
        return -1;
    }
    int fd = bpf_program__fd(program);
    uint64_t start = monotonic_ns();
    for (unsigned int iteration = 0; iteration < repeat; ++iteration) {
        struct bpf_test_run_opts options = {.sz = sizeof(options)};
        if (capsule_test_run(fd, &options)) {
            return -1;
        }
    }
    *duration = (monotonic_ns() - start) / repeat;
    return 0;
}

static int expect_yield(const volatile struct yield_test_state* state, uint64_t stage, uint64_t request, uint64_t continuation) {
    return state->result.status == CAPSULE_YIELD && !state->result.code && state->result.continuation == continuation && state->output == YIELD_TEST_SENTINEL &&
        state->stage == stage && state->request == request;
}

int main(int argc, char** argv) {
    if (argc != 2) {
        fprintf(stderr, "usage: yield_test_host OBJECT\n");
        return 2;
    }

    struct bpf_object* object = bpf_object__open_file(argv[1], NULL);
    size_t config_size = 0;
    struct bpf_map* config_map = object ? bpf_object__find_map_by_name(object, ".rodata.bpfconfig") : NULL;
    const struct __bpf_capsule_object_config* config = config_map ? bpf_map__initial_value(config_map, &config_size) : NULL;
    int uses_arena = config && config_size >= sizeof(*config) ? (int)config->uses_arena : -1;
    if (!object || uses_arena < 0 || capsule_test_load_object(object) || bpf_capsule_finish_initialization(object)) {
        fprintf(stderr, "cannot load yield test object\n");
        bpf_object__close(object);
        return 1;
    }
    struct bpf_capsule_memory memory;
    if (bpf_capsule_memory(object, &memory)) {
        fprintf(stderr, "cannot map Capsule memory\n");
        bpf_object__close(object);
        return 1;
    }

    size_t size = 0;
    struct bpf_map* map = bpf_object__find_map_by_name(object, ".data.yieldtest");
    volatile struct yield_test_state* state = map ? bpf_map__initial_value(map, &size) : NULL;
    size_t controls_size = 0;
    struct bpf_map* controls_map = bpf_object__find_map_by_name(object, ".bss.bpfctrl");
    volatile struct __bpf_capsule_fiber_control* controls = controls_map ? bpf_map__initial_value(controls_map, &controls_size) : NULL;
    int error = !state || size < sizeof(*state) || !controls || controls_size < sizeof(*controls) || run(object, "yield_test_start");
    uint64_t continuation = state ? state->first_continuation : BPF_CAPSULE_NO_CONTINUATION;
    int pass = !error && continuation != BPF_CAPSULE_NO_CONTINUATION && expect_yield(state, 1, 8, continuation);

    unsigned char replacement[32];
    uint64_t replacement_checksum = 0;
    for (unsigned int index = 0; index < sizeof(replacement); ++index) {
        replacement[index] = (unsigned char)(0xa0u + index);
        replacement_checksum += (uint64_t)replacement[index] * (index + 1u);
    }
    unsigned char observed[sizeof(replacement)];
    if (pass) {
        memset(observed, 0, sizeof(observed));
        pass = !bpf_capsule_memory_read(&memory, observed, state->stack_probe_address, sizeof(observed)) &&
            !bpf_capsule_memory_write(&memory, state->stack_probe_address, replacement, sizeof(replacement)) && memcmp(observed, replacement, sizeof(observed));
    }

    if (pass) {
        error = run(object, "yield_test_first_continue");
        pass = !error && state->result.continuation != continuation && expect_yield(state, 2, 54, state->result.continuation);
    }
    if (pass) {
        state->stale_continuation = continuation;
        error = run(object, "yield_test_stale_continue");
        pass = !error && state->stale_result.status == CAPSULE_EXITED && state->stale_result.code == CAPSULE_ERROR_STALE_CONTINUATION &&
            state->stale_result.continuation == BPF_CAPSULE_NO_CONTINUATION && state->result.status == CAPSULE_YIELD;
    }
    if (pass) {
        error = run(object, "yield_test_second_continue");
        pass = !error && state->result.status == CAPSULE_OK && !state->result.code && state->result.continuation == BPF_CAPSULE_NO_CONTINUATION &&
            state->stage == 3 && state->output == 128;
        pass = pass && state->stack_probe_checksum == replacement_checksum;
    }
    if (pass) {
        state->stale_continuation = continuation;
        error = run(object, "yield_test_stale_continue");
        pass = !error && state->stale_result.status == CAPSULE_EXITED && state->stale_result.code == CAPSULE_ERROR_STALE_CONTINUATION &&
            state->stale_result.continuation == BPF_CAPSULE_NO_CONTINUATION;
    }

    // Re-lease the same warm fiber to unrelated work. The retired token must
    // remain stale even though its low fiber bits name an active computation.
    if (pass) {
        error = run(object, "yield_test_start");
        pass = !error && state->result.status == CAPSULE_YIELD && state->result.continuation != continuation;
    }
    if (pass) {
        state->stale_continuation = continuation;
        error = run(object, "yield_test_stale_continue");
        pass = !error && state->stale_result.status == CAPSULE_EXITED && state->stale_result.code == CAPSULE_ERROR_STALE_CONTINUATION &&
            state->result.status == CAPSULE_YIELD;
    }
    if (pass) {
        error = run(object, "yield_test_reset_current");
        pass = !error && state->stale_result.status == CAPSULE_OK;
    }

    // A valid token whose saved stack state is missing is terminal. Even this
    // corrupt-state path must return its only fiber to the pool.
    if (pass && !uses_arena) {
        error = run(object, "yield_test_start");
        pass = !error && state->result.status == CAPSULE_YIELD;
    }
    if (pass && !uses_arena) {
        // Continuation tokens encode the 16-bit fiber index in their low
        // bits. Deliberately damage that fiber's saved stack through the
        // runtime control map, then consume the otherwise valid token. The
        // arena tier detects the missing stack while claiming the token and
        // therefore never acquires a fiber that needs releasing here.
        uint32_t fiber = (uint32_t)state->result.continuation & 0xffffu;
        pass = fiber < controls_size / sizeof(*controls);
        if (pass) {
            controls[fiber].stack_cursor = 0;
            state->stale_continuation = state->result.continuation;
            error = run(object, "yield_test_stale_continue");
        }
        pass = pass && !error && state->stale_result.status == CAPSULE_EXITED && state->stale_result.code == CAPSULE_ERROR_NOT_PENDING &&
            state->stale_result.continuation == BPF_CAPSULE_NO_CONTINUATION;
    }
    if (pass) {
        error = run(object, "yield_baseline_run");
        pass = !error && state->benchmark_result.status == CAPSULE_OK && state->benchmark_output == 72;
    }
    if (pass) {
        error = run(object, "yield_benchmark_run");
        pass = !error && state->benchmark_result.status == CAPSULE_OK && state->benchmark_output == 72;
    }

    uint64_t baseline_ns = 0;
    uint64_t yielded_ns = 0;
    if (pass) {
        error = measure(object, "yield_baseline_run", 1000, &baseline_ns);
        pass = !error && state->benchmark_result.status == CAPSULE_OK && state->benchmark_output == 72;
    }
    if (pass) {
        error = measure(object, "yield_benchmark_run", 1000, &yielded_ns);
        pass = !error && state->benchmark_result.status == CAPSULE_OK && state->benchmark_output == 72;
    }

    printf(pass ? "YIELD-PASS\n" : "YIELD-FAIL\n");
    if (pass) {
        printf(
            "yield benchmark: %llu ns yielded, %llu ns baseline, %u round trips, %+.1f ns/round-trip delta\n", yielded_ns, baseline_ns, YIELD_TEST_ROUNDS,
            ((double)yielded_ns - (double)baseline_ns) / YIELD_TEST_ROUNDS
        );
    }
    if (!pass && state) {
        fprintf(
            stderr, "syscall=%d status=%u code=%lld continuation=%llu first=%llu stage=%llu request=%llu response=%llu output=%llx stale=%u/%lld\n", error,
            state->result.status, (long long)state->result.code, (unsigned long long)state->result.continuation, (unsigned long long)state->first_continuation,
            state->stage, state->request, state->response, state->output, state->stale_result.status, (long long)state->stale_result.code
        );
    }
    bpf_object__close(object);
    return pass ? 0 : 1;
}
