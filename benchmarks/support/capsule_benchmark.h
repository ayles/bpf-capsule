// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
// In-process metric collection for Google Benchmark harnesses. No
// subprocesses: static instruction counts come from libbpf
// (bpf_program__insn_cnt), and verifier processed-instruction counts are
// parsed from each program's own verifier log, captured through
// bpf_program__set_log_buf around the load.
#pragma once

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <benchmark/benchmark.h>

// Sum of static (post-compile, pre-verifier) instruction counts across every
// program in the object. Valid after open, before or after load.
static inline uint64_t capsule_bench_static_insns(struct bpf_object* object) {
    uint64_t total = 0;
    struct bpf_program* program;
    bpf_object__for_each_program(program, object) {
        total += bpf_program__insn_cnt(program);
    }
    return total;
}

struct capsule_bench_load_stats {
    uint64_t processed_insns_max; // worst program in the object
    uint64_t processed_insns_sum; // whole object
};

static inline void capsule_bench_release_verifier_logs(struct bpf_object* object) {
    struct bpf_program* program;
    bpf_object__for_each_program(program, object) {
        size_t size = 0;
        const char* log = bpf_program__log_buf(program, &size);
        if (log) {
            bpf_program__set_log_level(program, 0);
            // If libbpf ever refuses the detach, retaining the allocation is
            // safer than leaving it with a dangling log pointer.
            if (!bpf_program__set_log_buf(program, NULL, 0)) {
                free((void*)log);
            }
        }
    }
}

// Give every program a verifier-stats log buffer. Call after open, before
// load. BPF_LOG_STATS is bit 2 of attr.log_level. Setup is transactional: an
// error detaches every buffer already installed.
static inline int capsule_bench_arm_verifier_stats(struct bpf_object* object) {
    struct bpf_program* program;
    bpf_object__for_each_program(program, object) {
        char* log = (char*)calloc(1, 64u * 1024u);
        if (!log) {
            capsule_bench_release_verifier_logs(object);
            return -1;
        }
        if (bpf_program__set_log_buf(program, log, 64u * 1024u)) {
            free(log);
            capsule_bench_release_verifier_logs(object);
            return -1;
        }
        if (bpf_program__set_log_level(program, 1u << 2)) {
            capsule_bench_release_verifier_logs(object);
            return -1;
        }
    }
    return 0;
}

// Harvest "processed N insns" from each armed log and release the buffers.
// Call after load (successful or not).
static inline void capsule_bench_collect_verifier_stats(struct bpf_object* object, struct capsule_bench_load_stats* stats) {
    stats->processed_insns_max = 0;
    stats->processed_insns_sum = 0;
    struct bpf_program* program;
    bpf_object__for_each_program(program, object) {
        size_t size = 0;
        const char* log = bpf_program__log_buf(program, &size);
        if (log && size) {
            const char* cursor = strstr(log, "processed ");
            if (cursor) {
                uint64_t processed = strtoull(cursor + strlen("processed "), NULL, 10);
                stats->processed_insns_sum += processed;
                if (processed > stats->processed_insns_max) {
                    stats->processed_insns_max = processed;
                }
            }
        }
    }
    capsule_bench_release_verifier_logs(object);
}

static inline void capsule_bench_report(benchmark::State& state, uint64_t static_insns, const struct capsule_bench_load_stats& stats) {
    state.counters["static_insns"] = benchmark::Counter((double)static_insns);
    state.counters["verifier_insns_max"] = benchmark::Counter((double)stats.processed_insns_max);
    state.counters["verifier_insns_sum"] = benchmark::Counter((double)stats.processed_insns_sum);
}
