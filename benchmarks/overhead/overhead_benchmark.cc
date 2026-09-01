// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
// A small cost model for the transformed ABI.  Each BPF row is paired with a
// direct-BPF floor; the scalar rows also have a native AArch64 compiler floor.
#include <benchmark/benchmark.h>

#include <bpf/libbpf.h>

#include "bpf_capsule_host.h"
#include "overhead.h"
#include "overhead.skel.h"

#include <chrono>
#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstring>

namespace {

uint64_t arithmeticStep(uint64_t value, uint32_t index) {
    return value * 1664525u + static_cast<uint64_t>(index) + 1013904223u;
}

__attribute__((noinline)) uint64_t nativeByvalLeaf(overhead_byval argument, uint32_t index) {
    return arithmeticStep(argument.first + (argument.second ^ argument.third), index);
}

uint64_t byvalStep(uint64_t value, uint32_t index) {
    overhead_byval argument = {value, value ^ 0x9e3779b97f4a7c15ull, index};
    return nativeByvalLeaf(argument, index);
}

struct Loaded {
    struct overhead* Skeleton = nullptr;
    struct bpf_capsule Capsule = {};
    volatile struct overhead_state* State = nullptr;
    const char* Error = nullptr;

    Loaded() {
        if (geteuid() != 0) {
            Error = "loading BPF objects needs root";
            return;
        }
        Skeleton = overhead__open();
        struct bpf_capsule_config config = {};
        config.fiber_count = 1;
        if (!Skeleton || bpf_capsule_configure(&Capsule, Skeleton->obj, config) || overhead__load(Skeleton) || bpf_capsule_initialize(&Capsule)) {
            Error = "cannot load overhead BPF object";
            return;
        }
        State = &Skeleton->data_overhead->overhead_state;
        struct bpf_test_run_opts options = {};
        options.sz = sizeof(options);
        if (bpf_prog_test_run_opts(bpf_program__fd(Skeleton->progs.overhead_prepare), &options) || State->capsule.status != CAPSULE_OK ||
            !State->logical_words) {
            Error = "cannot initialize Capsule memory";
            return;
        }

        auto run = [&](struct bpf_program* program) { return bpf_prog_test_run_opts(bpf_program__fd(program), &options) == 0; };
        if (!run(Skeleton->progs.overhead_direct_pressure_call_loop)) {
            Error = "cannot run direct pressure-loop validation";
            return;
        }
        uint64_t expected = State->result;
        struct bpf_program* chunks[] = {
            Skeleton->progs.overhead_maygoto_pressure_call_loop,
            Skeleton->progs.overhead_flat_stack_pressure_call_loop,
            Skeleton->progs.overhead_flat_map_pressure_call_loop,
            Skeleton->progs.overhead_iterator_pressure_call_loop,
            Skeleton->progs.overhead_chunked_pressure_call_loop_1,
            Skeleton->progs.overhead_chunked_pressure_call_loop_2,
            Skeleton->progs.overhead_chunked_pressure_call_loop_4,
            Skeleton->progs.overhead_chunked_pressure_call_loop_8,
            Skeleton->progs.overhead_chunked_pressure_call_loop_16,
            Skeleton->progs.overhead_chunked_pressure_call_loop_32,
            Skeleton->progs.overhead_chunked_pressure_call_loop_64,
        };
        for (struct bpf_program* program : chunks) {
            if (!run(program) || State->result != expected) {
                Error = "chunked pressure loop produced a wrong result";
                return;
            }
        }
        if (!run(Skeleton->progs.overhead_capsule_precomputed_values_call_loop)) {
            Error = "cannot run precomputed-value validation";
            return;
        }
        uint64_t scheduledExpected = State->result;
        if (!run(Skeleton->progs.overhead_capsule_postcomputed_values_call_loop) || State->result != scheduledExpected) {
            Error = "pre/post-computed loops produced different results";
            return;
        }
        if (!run(Skeleton->progs.overhead_capsule_pressure_call_loop) || State->capsule.status != CAPSULE_OK || State->result != expected) {
            Error = "Capsule pressure loop produced a wrong result";
            return;
        }
        uint64_t byvalExpected = 7;
        for (uint32_t index = 0; index < OVERHEAD_ARITHMETIC_TRIPS; ++index) {
            byvalExpected = byvalStep(byvalExpected, index);
        }
        if (!run(Skeleton->progs.overhead_capsule_byval_call_loop) || State->capsule.status != CAPSULE_OK || State->result != byvalExpected) {
            Error = "Capsule by-value call loop produced a wrong result";
        }
    }

    ~Loaded() {
        (void)bpf_capsule_release(&Capsule);
        overhead__destroy(Skeleton);
    }
};

Loaded& loaded() {
    static Loaded value;
    return value;
}

using Program = struct bpf_program* (*)(struct overhead*);

template <Program program, uint32_t repeat>
void BpfCase(benchmark::State& benchmarkState) {
    Loaded& object = loaded();
    if (object.Error) {
        benchmarkState.SkipWithError(object.Error);
        return;
    }
    struct bpf_test_run_opts options = {};
    options.sz = sizeof(options);
    int fd = bpf_program__fd(program(object.Skeleton));
    for (auto _ : benchmarkState) {
        auto begin = std::chrono::steady_clock::now();
        int error = 0;
        for (uint32_t index = 0; index < repeat && !error; ++index) {
            error = bpf_prog_test_run_opts(fd, &options);
        }
        auto end = std::chrono::steady_clock::now();
        if (error) {
            char message[128];
            std::snprintf(message, sizeof(message), "BPF_PROG_TEST_RUN failed: %s", std::strerror(errno));
            benchmarkState.SkipWithError(message);
            break;
        }
        benchmarkState.SetIterationTime(std::chrono::duration<double>(end - begin).count() / repeat);
        benchmark::DoNotOptimize(object.State->result);
    }
    benchmarkState.counters["kernel_duration_ns"] = options.duration;
}

struct bpf_program* DirectEmpty(struct overhead* object) {
    return object->progs.overhead_direct_empty;
}
struct bpf_program* CapsuleEmpty(struct overhead* object) {
    return object->progs.overhead_capsule_empty;
}
struct bpf_program* DirectArithmetic(struct overhead* object) {
    return object->progs.overhead_direct_arithmetic;
}
struct bpf_program* CapsuleArithmetic(struct overhead* object) {
    return object->progs.overhead_capsule_arithmetic;
}
struct bpf_program* DirectModulo(struct overhead* object) {
    return object->progs.overhead_direct_modulo;
}
struct bpf_program* CapsuleModulo(struct overhead* object) {
    return object->progs.overhead_capsule_modulo;
}
struct bpf_program* DirectDynamicLoop(struct overhead* object) {
    return object->progs.overhead_direct_dynamic_loop;
}
struct bpf_program* CapsuleDynamicLoop(struct overhead* object) {
    return object->progs.overhead_capsule_dynamic_loop;
}
struct bpf_program* DirectDynamicCallLoop(struct overhead* object) {
    return object->progs.overhead_direct_dynamic_call_loop;
}
struct bpf_program* CapsuleDynamicCallLoop(struct overhead* object) {
    return object->progs.overhead_capsule_dynamic_call_loop;
}
struct bpf_program* CapsuleByValCallLoop(struct overhead* object) {
    return object->progs.overhead_capsule_byval_call_loop;
}
struct bpf_program* DirectPressureCallLoop(struct overhead* object) {
    return object->progs.overhead_direct_pressure_call_loop;
}
struct bpf_program* FlatStackPressureCallLoop(struct overhead* object) {
    return object->progs.overhead_flat_stack_pressure_call_loop;
}
struct bpf_program* FlatMapPressureCallLoop(struct overhead* object) {
    return object->progs.overhead_flat_map_pressure_call_loop;
}
struct bpf_program* MayGotoPressureCallLoop(struct overhead* object) {
    return object->progs.overhead_maygoto_pressure_call_loop;
}
struct bpf_program* IteratorPressureCallLoop(struct overhead* object) {
    return object->progs.overhead_iterator_pressure_call_loop;
}
#define CHUNK_PROGRAM(N) \
    struct bpf_program* ChunkedPressureCallLoop##N(struct overhead* object) { \
        return object->progs.overhead_chunked_pressure_call_loop_##N; \
    }
CHUNK_PROGRAM(1)
CHUNK_PROGRAM(2)
CHUNK_PROGRAM(4)
CHUNK_PROGRAM(8)
CHUNK_PROGRAM(16)
CHUNK_PROGRAM(32)
CHUNK_PROGRAM(64)
struct bpf_program* CapsulePressureCallLoop(struct overhead* object) {
    return object->progs.overhead_capsule_pressure_call_loop;
}
struct bpf_program* CapsuleDeadValuesCallLoop(struct overhead* object) {
    return object->progs.overhead_capsule_dead_values_call_loop;
}
struct bpf_program* CapsuleInvariantValuesCallLoop(struct overhead* object) {
    return object->progs.overhead_capsule_invariant_values_call_loop;
}
struct bpf_program* CapsulePrecomputedValuesCallLoop(struct overhead* object) {
    return object->progs.overhead_capsule_precomputed_values_call_loop;
}
struct bpf_program* CapsulePostcomputedValuesCallLoop(struct overhead* object) {
    return object->progs.overhead_capsule_postcomputed_values_call_loop;
}
struct bpf_program* CapsuleRecursiveChain(struct overhead* object) {
    return object->progs.overhead_capsule_recursive_chain;
}
struct bpf_program* DirectMemory64(struct overhead* object) {
    return object->progs.overhead_direct_memory64;
}
struct bpf_program* CapsuleMemory64(struct overhead* object) {
    return object->progs.overhead_capsule_memory64;
}
struct bpf_program* DirectCombined(struct overhead* object) {
    return object->progs.overhead_direct_combined;
}
struct bpf_program* CapsuleCombined(struct overhead* object) {
    return object->progs.overhead_capsule_combined;
}
struct bpf_program* DirectPointerChase(struct overhead* object) {
    return object->progs.overhead_direct_pointer_chase;
}
struct bpf_program* CapsulePointerChase(struct overhead* object) {
    return object->progs.overhead_capsule_pointer_chase;
}

void NativeEmpty(benchmark::State& state) {
    for (auto _ : state) {
        benchmark::DoNotOptimize(uint64_t{1});
    }
}

void NativeArithmetic(benchmark::State& state) {
    for (auto _ : state) {
        uint64_t value = 7;
        for (uint32_t index = 0; index < OVERHEAD_ARITHMETIC_TRIPS; ++index) {
            value = arithmeticStep(value, index);
        }
        benchmark::DoNotOptimize(value);
    }
}

void NativeModulo(benchmark::State& state) {
    static volatile int64_t divisor = 1000003;
    for (auto _ : state) {
        int64_t value = 7;
        for (uint32_t index = 0; index < OVERHEAD_ARITHMETIC_TRIPS; ++index) {
            value = (value + static_cast<int64_t>(index) * 17) % divisor;
        }
        benchmark::DoNotOptimize(value);
    }
}

void NativeDynamicLoop(benchmark::State& state) {
    static volatile uint32_t trips = OVERHEAD_ARITHMETIC_TRIPS;
    for (auto _ : state) {
        uint64_t value = 7;
        for (uint32_t index = 0; index < trips; ++index) {
            value = arithmeticStep(value, index);
        }
        benchmark::DoNotOptimize(value);
    }
}

__attribute__((noinline)) uint64_t nativeDynamicLeaf(uint64_t value, uint32_t index) {
    return arithmeticStep(value, index);
}

void NativeDynamicCallLoop(benchmark::State& state) {
    static volatile uint32_t trips = OVERHEAD_ARITHMETIC_TRIPS;
    for (auto _ : state) {
        uint64_t value = 7;
        for (uint32_t index = 0; index < trips; ++index) {
            value = nativeDynamicLeaf(value, index);
        }
        benchmark::DoNotOptimize(value);
    }
}

void NativeByValCallLoop(benchmark::State& state) {
    static volatile uint32_t trips = OVERHEAD_ARITHMETIC_TRIPS;
    for (auto _ : state) {
        uint64_t value = 7;
        for (uint32_t index = 0; index < trips; ++index) {
            value = byvalStep(value, index);
        }
        benchmark::DoNotOptimize(value);
    }
}

void NativePressureCallLoop(benchmark::State& state) {
    static volatile uint32_t trips = OVERHEAD_ARITHMETIC_TRIPS;
    for (auto _ : state) {
        uint64_t a = 1, b = 2, c = 3, d = 4, e = 5, f = 6, g = 7, h = 8;
        for (uint32_t index = 0; index < trips; ++index) {
            uint64_t next = nativeDynamicLeaf(a + h, index);
            a = next + b;
            b ^= next + c;
            c += next ^ d;
            d = (d + e) ^ next;
            e += f ^ next;
            f = (f ^ g) + next;
            g += h + next;
            h ^= a + next;
        }
        benchmark::DoNotOptimize(a ^ b ^ c ^ d ^ e ^ f ^ g ^ h);
    }
}

void NativeMemory64(benchmark::State& state) {
    static volatile uint64_t words[OVERHEAD_MEMORY_WORDS];
    for (auto _ : state) {
        uint64_t value = 7;
        for (uint32_t index = 0; index < OVERHEAD_MEMORY_WORDS; ++index) {
            uint64_t next = arithmeticStep(value + words[index], index);
            words[index] = next;
            value ^= next;
        }
        benchmark::DoNotOptimize(value);
    }
}

void NativeCombined(benchmark::State& state) {
    static volatile uint64_t words[OVERHEAD_MEMORY_WORDS];
    for (auto _ : state) {
        uint64_t value = 7;
        for (uint32_t index = 0; index < OVERHEAD_ARITHMETIC_TRIPS; ++index) {
            uint32_t slot = index & (OVERHEAD_MEMORY_WORDS - 1u);
            uint64_t next = arithmeticStep(value + words[slot], index);
            words[slot] = next;
            value ^= next;
        }
        benchmark::DoNotOptimize(value);
    }
}

void NativePointerChase(benchmark::State& state) {
    static overhead_node nodes[OVERHEAD_MEMORY_WORDS];
    static bool initialized = false;
    if (!initialized) {
        for (uint32_t index = 0; index < OVERHEAD_MEMORY_WORDS; ++index) {
            nodes[index].next = (index * 17u + 1u) & (OVERHEAD_MEMORY_WORDS - 1u);
            nodes[index].value = index;
        }
        initialized = true;
    }
    for (auto _ : state) {
        uint32_t slot = 0;
        uint64_t value = 7;
        for (uint32_t index = 0; index < OVERHEAD_ARITHMETIC_TRIPS; ++index) {
            slot = nodes[slot].next;
            uint64_t next = arithmeticStep(value + nodes[slot].value, index);
            nodes[slot].value = next;
            value ^= next;
        }
        benchmark::DoNotOptimize(value);
    }
}

constexpr auto BpfIterations = 21;
BENCHMARK(NativeEmpty);
BENCHMARK_TEMPLATE(BpfCase, DirectEmpty, 10000)->UseManualTime()->Iterations(BpfIterations);
BENCHMARK_TEMPLATE(BpfCase, CapsuleEmpty, 1000)->UseManualTime()->Iterations(BpfIterations);
BENCHMARK(NativeArithmetic);
BENCHMARK_TEMPLATE(BpfCase, DirectArithmetic, 1000)->UseManualTime()->Iterations(BpfIterations);
BENCHMARK_TEMPLATE(BpfCase, CapsuleArithmetic, 100)->UseManualTime()->Iterations(BpfIterations);
BENCHMARK(NativeModulo);
BENCHMARK_TEMPLATE(BpfCase, DirectModulo, 1000)->UseManualTime()->Iterations(BpfIterations);
BENCHMARK_TEMPLATE(BpfCase, CapsuleModulo, 100)->UseManualTime()->Iterations(BpfIterations);
BENCHMARK(NativeDynamicLoop);
BENCHMARK_TEMPLATE(BpfCase, DirectDynamicLoop, 1000)->UseManualTime()->Iterations(BpfIterations);
BENCHMARK_TEMPLATE(BpfCase, CapsuleDynamicLoop, 100)->UseManualTime()->Iterations(BpfIterations);
BENCHMARK(NativeDynamicCallLoop);
BENCHMARK_TEMPLATE(BpfCase, DirectDynamicCallLoop, 1000)->UseManualTime()->Iterations(BpfIterations);
BENCHMARK_TEMPLATE(BpfCase, CapsuleDynamicCallLoop, 100)->UseManualTime()->Iterations(BpfIterations);
BENCHMARK(NativeByValCallLoop);
BENCHMARK_TEMPLATE(BpfCase, CapsuleByValCallLoop, 100)->UseManualTime()->Iterations(BpfIterations);
BENCHMARK(NativePressureCallLoop);
BENCHMARK_TEMPLATE(BpfCase, DirectPressureCallLoop, 1000)->UseManualTime()->Iterations(BpfIterations);
BENCHMARK_TEMPLATE(BpfCase, FlatStackPressureCallLoop, 1000)->UseManualTime()->Iterations(BpfIterations);
BENCHMARK_TEMPLATE(BpfCase, FlatMapPressureCallLoop, 1000)->UseManualTime()->Iterations(BpfIterations);
BENCHMARK_TEMPLATE(BpfCase, MayGotoPressureCallLoop, 1000)->UseManualTime()->Iterations(BpfIterations);
BENCHMARK_TEMPLATE(BpfCase, IteratorPressureCallLoop, 1000)->UseManualTime()->Iterations(BpfIterations);
BENCHMARK_TEMPLATE(BpfCase, ChunkedPressureCallLoop1, 1000)->UseManualTime()->Iterations(BpfIterations);
BENCHMARK_TEMPLATE(BpfCase, ChunkedPressureCallLoop2, 1000)->UseManualTime()->Iterations(BpfIterations);
BENCHMARK_TEMPLATE(BpfCase, ChunkedPressureCallLoop4, 1000)->UseManualTime()->Iterations(BpfIterations);
BENCHMARK_TEMPLATE(BpfCase, ChunkedPressureCallLoop8, 1000)->UseManualTime()->Iterations(BpfIterations);
BENCHMARK_TEMPLATE(BpfCase, ChunkedPressureCallLoop16, 1000)->UseManualTime()->Iterations(BpfIterations);
BENCHMARK_TEMPLATE(BpfCase, ChunkedPressureCallLoop32, 1000)->UseManualTime()->Iterations(BpfIterations);
BENCHMARK_TEMPLATE(BpfCase, ChunkedPressureCallLoop64, 1000)->UseManualTime()->Iterations(BpfIterations);
BENCHMARK_TEMPLATE(BpfCase, CapsulePressureCallLoop, 100)->UseManualTime()->Iterations(BpfIterations);
BENCHMARK_TEMPLATE(BpfCase, CapsuleDeadValuesCallLoop, 100)->UseManualTime()->Iterations(BpfIterations);
BENCHMARK_TEMPLATE(BpfCase, CapsuleInvariantValuesCallLoop, 100)->UseManualTime()->Iterations(BpfIterations);
BENCHMARK_TEMPLATE(BpfCase, CapsulePrecomputedValuesCallLoop, 100)->UseManualTime()->Iterations(BpfIterations);
BENCHMARK_TEMPLATE(BpfCase, CapsulePostcomputedValuesCallLoop, 100)->UseManualTime()->Iterations(BpfIterations);
BENCHMARK_TEMPLATE(BpfCase, CapsuleRecursiveChain, 100)->UseManualTime()->Iterations(BpfIterations);
BENCHMARK(NativeMemory64);
BENCHMARK_TEMPLATE(BpfCase, DirectMemory64, 1000)->UseManualTime()->Iterations(BpfIterations);
BENCHMARK_TEMPLATE(BpfCase, CapsuleMemory64, 100)->UseManualTime()->Iterations(BpfIterations);
BENCHMARK(NativeCombined);
BENCHMARK_TEMPLATE(BpfCase, DirectCombined, 1000)->UseManualTime()->Iterations(BpfIterations);
BENCHMARK_TEMPLATE(BpfCase, CapsuleCombined, 100)->UseManualTime()->Iterations(BpfIterations);
BENCHMARK(NativePointerChase);
BENCHMARK_TEMPLATE(BpfCase, DirectPointerChase, 1000)->UseManualTime()->Iterations(BpfIterations);
BENCHMARK_TEMPLATE(BpfCase, CapsulePointerChase, 100)->UseManualTime()->Iterations(BpfIterations);

} // namespace

BENCHMARK_MAIN();
