// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
// The Lua interpreter as the reference workload benchmark: script execution
// wall time per full drive (entry + drains), with drains, static instruction
// count, and verifier budget as counters. Red until the passes exist, like
// its test.
#include "capsule_benchmark.h"

#include "bpf_capsule_host.h"
#include "lua_runner_ctrl.h"
#include "lua_runner.skel.h"

#include <bpf/bpf.h>

#include <cstdlib>
#include <fstream>
#include <string>

namespace {

void destroy_lua(struct lua_runner* skeleton, struct bpf_capsule* capsule) {
    (void)bpf_capsule_release(capsule);
    lua_runner__destroy(skeleton);
}

int drive(struct lua_runner* skeleton, volatile struct lua_runner_ctrl* control, int entry_fd, uint64_t* drains) {
    struct bpf_test_run_opts options = {};
    options.sz = sizeof(options);
    if (bpf_prog_test_run_opts(entry_fd, &options)) {
        return -1;
    }
    int drain_fd = bpf_program__fd(skeleton->progs.lua_drain);
    while (control->capsule.status == CAPSULE_PENDING) {
        if (*drains > 2000000) {
            errno = ETIMEDOUT;
            return -1;
        }
        if (bpf_prog_test_run_opts(drain_fd, &options)) {
            return -1;
        }
        ++*drains;
    }
    return 0;
}

void BM_LuaScript(benchmark::State& state) {
    if (geteuid() != 0) {
        state.SkipWithMessage("loading BPF objects needs root");
        return;
    }
    const char* scriptPath = std::getenv("BPF_CAPSULE_LUA_SCRIPT");
    std::ifstream file(scriptPath ? scriptPath : LUA_BENCH_SCRIPT);
    std::string script((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
    if (script.empty()) {
        state.SkipWithError("missing script");
        return;
    }

    struct lua_runner* skeleton = lua_runner__open();
    struct bpf_capsule capsule = {};
    struct bpf_capsule_config config = {};
    config.fiber_count = 1;
    config.heap_bytes = 16ull << 20;
    capsule_bench_load_stats stats = {};
    if (!skeleton || bpf_capsule_configure(&capsule, skeleton->obj, config) || capsule_bench_arm_verifier_stats(skeleton->obj) ||
        lua_runner__load(skeleton) != 0) {
        state.SkipWithError("cannot load Capsule Lua");
        destroy_lua(skeleton, &capsule);
        return;
    }
    capsule_bench_collect_verifier_stats(skeleton->obj, &stats);
    if (bpf_capsule_initialize(&capsule)) {
        state.SkipWithError("cannot initialize Capsule Lua");
        destroy_lua(skeleton, &capsule);
        return;
    }
    volatile struct lua_runner_ctrl* control = &skeleton->data_lua_runner->lua_runner_control;
    uint64_t drains = 0;
    if (drive(skeleton, control, bpf_program__fd(skeleton->progs.lua_prepare), &drains) || control->capsule.status != CAPSULE_OK ||
        script.size() > control->script.capacity || bpf_capsule_memcpy(&capsule, control->script.address, script.data(), script.size())) {
        state.SkipWithError("cannot stage the script");
        destroy_lua(skeleton, &capsule);
        return;
    }
    control->script.size = script.size();
    control->input.size = 0;
    uint64_t run_drains = 0;
    uint64_t runs = 0;
    for (auto _ : state) {
        if (drive(skeleton, control, bpf_program__fd(skeleton->progs.lua_run), &run_drains) || control->capsule.status != CAPSULE_OK) {
            state.SkipWithError("script run failed");
            break;
        }
        runs++;
    }
    capsule_bench_report(state, capsule_bench_static_insns(skeleton->obj), stats);
    if (runs) {
        state.counters["drains_per_run"] = benchmark::Counter((double)run_drains / (double)runs);
    }
    destroy_lua(skeleton, &capsule);
}
BENCHMARK(BM_LuaScript)->Unit(benchmark::kMillisecond);

} // namespace

BENCHMARK_MAIN();
