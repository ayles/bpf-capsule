// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
// The minimal-program benchmarks: load/verify cost of the smallest complete
// capsule object, and the per-entry cost of a real capsule_call running
// recursive fib(20) through the software stack.
#include "capsule_benchmark.h"

#include "bpf_capsule_host.h"
#include "smoke.h"
#include "smoke.skel.h"

namespace {

constexpr uint64_t kMaxDrainsPerRun = 100'000;

void destroy_smoke(struct smoke* skeleton, struct bpf_capsule* capsule) {
    (void)bpf_capsule_release(capsule);
    smoke__destroy(skeleton);
}

void BM_SmokeLoad(benchmark::State& state) {
    if (geteuid() != 0) {
        state.SkipWithMessage("loading BPF objects needs root");
        return;
    }
    uint64_t static_insns = 0;
    capsule_bench_load_stats stats = {};
    for (auto _ : state) {
        struct smoke* skeleton = smoke__open();
        struct bpf_capsule capsule = {};
        struct bpf_capsule_config config = {};
        config.fiber_count = 1;
        if (!skeleton || bpf_capsule_configure(&capsule, skeleton->obj, config)) {
            state.SkipWithError("open/configure failed");
            destroy_smoke(skeleton, &capsule);
            return;
        }
        if (capsule_bench_arm_verifier_stats(skeleton->obj)) {
            state.SkipWithError("cannot allocate verifier logs");
            destroy_smoke(skeleton, &capsule);
            return;
        }
        if (smoke__load(skeleton) != 0) {
            state.SkipWithError("load failed");
            destroy_smoke(skeleton, &capsule);
            return;
        }
        capsule_bench_collect_verifier_stats(skeleton->obj, &stats);
        static_insns = capsule_bench_static_insns(skeleton->obj);
        destroy_smoke(skeleton, &capsule);
    }
    capsule_bench_report(state, static_insns, stats);
}
BENCHMARK(BM_SmokeLoad)->Unit(benchmark::kMillisecond);

void BM_SmokeFib20(benchmark::State& state) {
    if (geteuid() != 0) {
        state.SkipWithMessage("loading BPF objects needs root");
        return;
    }
    struct smoke* skeleton = smoke__open();
    struct bpf_capsule capsule = {};
    struct bpf_capsule_config config = {};
    config.fiber_count = 1;
    if (!skeleton || bpf_capsule_configure(&capsule, skeleton->obj, config) || smoke__load(skeleton) != 0 || bpf_capsule_initialize(&capsule)) {
        state.SkipWithError("cannot load smoke object");
        destroy_smoke(skeleton, &capsule);
        return;
    }
    volatile auto* st = &skeleton->data_smoke->smoke_state;
    st->input = 20;
    int run_fd = bpf_program__fd(skeleton->progs.smoke_run);
    int drain_fd = bpf_program__fd(skeleton->progs.smoke_drain);
    uint64_t drains = 0;
    uint64_t runs = 0;
    for (auto _ : state) {
        struct bpf_test_run_opts options = {};
        options.sz = sizeof(options);
        if (bpf_prog_test_run_opts(run_fd, &options)) {
            state.SkipWithError("test_run failed");
            break;
        }
        uint64_t run_drains = 0;
        while (st->capsule.status == CAPSULE_PENDING && run_drains < kMaxDrainsPerRun) {
            if (bpf_prog_test_run_opts(drain_fd, &options)) {
                state.SkipWithError("drain failed");
                break;
            }
            ++run_drains;
            ++drains;
        }
        if (st->capsule.status != CAPSULE_OK || st->output != 6765u) {
            state.SkipWithError("wrong result");
            break;
        }
        runs++;
    }
    if (runs) {
        state.counters["drains_per_run"] = benchmark::Counter((double)drains / (double)runs);
    }
    destroy_smoke(skeleton, &capsule);
}
BENCHMARK(BM_SmokeFib20)->Unit(benchmark::kMicrosecond);

} // namespace

BENCHMARK_MAIN();
