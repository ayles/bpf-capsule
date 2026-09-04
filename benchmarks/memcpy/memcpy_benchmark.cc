// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
// Compare the C library memcpy used from Capsule code with the native host
// implementation without perturbing the loop-packing choices of other cases.
#include <benchmark/benchmark.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "bpf_capsule_host.h"
#include "memcpy.h"
#include "memcpy.skel.h"

#include <chrono>
#include <cstdint>
#include <cstring>
#include <unistd.h>

namespace {

struct Loaded {
    struct memcpy* skeleton = nullptr;
    struct bpf_capsule capsule = {};
    volatile struct memcpy_state* state = nullptr;
    const char* error = nullptr;

    Loaded() {
        if (geteuid() != 0) {
            error = "loading BPF objects needs root";
            return;
        }
        skeleton = memcpy__open();
        struct bpf_capsule_config config = {};
        config.fiber_count = 1;
        if (!skeleton || bpf_capsule_configure(&capsule, skeleton->obj, config) || memcpy__load(skeleton) || bpf_capsule_initialize(&capsule)) {
            error = "cannot load memcpy BPF object";
            return;
        }
        state = &skeleton->data_memcpy->memcpy_state;
    }

    ~Loaded() {
        (void)bpf_capsule_release(&capsule);
        memcpy__destroy(skeleton);
    }
};

Loaded& loaded() {
    static Loaded value;
    return value;
}

void NativeMemcpy(benchmark::State& state) {
    static unsigned char source[MEMCPY_MAX_BYTES];
    static unsigned char destination[MEMCPY_MAX_BYTES];
    size_t bytes = static_cast<size_t>(state.range(0));
    source[0] = 0x12;
    source[bytes - 1] = 0x34;
    for (auto _ : state) {
        std::memcpy(destination, source, bytes);
        benchmark::DoNotOptimize(destination);
    }
    state.SetBytesProcessed(state.iterations() * static_cast<int64_t>(bytes));
}

void BpfMemcpy(benchmark::State& state) {
    Loaded& object = loaded();
    if (object.error) {
        state.SkipWithError(object.error);
        return;
    }
    object.state->bytes = static_cast<uint32_t>(state.range(0));
    struct bpf_test_run_opts options = {};
    options.sz = sizeof(options);
    int fd = bpf_program__fd(object.skeleton->progs.memcpy_run);
    for (auto _ : state) {
        auto begin = std::chrono::steady_clock::now();
        int error = bpf_prog_test_run_opts(fd, &options);
        auto end = std::chrono::steady_clock::now();
        if (error || object.state->capsule.status != CAPSULE_OK || object.state->result != 0x1234) {
            state.SkipWithError("Capsule memcpy failed");
            break;
        }
        state.SetIterationTime(std::chrono::duration<double>(end - begin).count());
    }
    state.SetBytesProcessed(state.iterations() * state.range(0));
    state.counters["kernel_duration_ns"] = options.duration;
}

BENCHMARK(NativeMemcpy)->RangeMultiplier(8)->Range(64, MEMCPY_MAX_BYTES);
BENCHMARK(BpfMemcpy)->RangeMultiplier(8)->Range(64, MEMCPY_MAX_BYTES)->UseManualTime()->Iterations(21);

} // namespace

BENCHMARK_MAIN();
