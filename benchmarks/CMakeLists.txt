# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
# Google Benchmark harnesses. Registered in ctest under the "bench" label so
# one `sudo ctest` runs tests and benchmarks together (CI-ready);
# `sudo ctest -L bench` runs only the benchmarks, `ctest -LE bench` only the
# tests. Run a binary directly for full control of --benchmark_* flags.
find_package(benchmark REQUIRED)

function(capsule_benchmark name)
    cmake_parse_arguments(ARG "" "" "SOURCES;INCLUDE_DIRECTORIES;DEPENDS" ${ARGN})
    add_executable(${name} ${ARG_SOURCES})
    target_include_directories(
        ${name} PRIVATE "${CMAKE_SOURCE_DIR}/src/runtime/guest" "${CMAKE_SOURCE_DIR}/src/runtime/host"
                        "${CMAKE_SOURCE_DIR}/benchmarks/support"
                        ${ARG_INCLUDE_DIRECTORIES}
    )
    target_link_libraries(${name} PRIVATE benchmark::benchmark ${BPF_CAPSULE_HOST_TARGET})
    if(ARG_DEPENDS)
        add_dependencies(${name} ${ARG_DEPENDS})
    endif()
    # Google Benchmark has no ctest discovery module; one entry per binary is
    # the standard integration. Every ctest run also leaves machine-readable
    # results under build/benchmark-results/. The Nix benchmark app combines
    # the three files for CI reporting and history.
    add_test(NAME ${name} COMMAND ${name} --benchmark_min_time=0.2s
                          --benchmark_out=${CMAKE_BINARY_DIR}/benchmark-results/${name}.json
                          --benchmark_out_format=json
    )
    set_tests_properties(${name} PROPERTIES LABELS "bench;privileged")
    if(BPF_CAPSULE_INSTALL_TEST_ARTIFACTS)
        install(TARGETS ${name}
                RUNTIME DESTINATION "${CMAKE_INSTALL_LIBEXECDIR}/bpf-capsule/benchmarks")
    endif()
endfunction()
file(MAKE_DIRECTORY "${CMAKE_BINARY_DIR}/benchmark-results")

capsule_benchmark(
    smoke_benchmark
    SOURCES pipeline-smoke/smoke_benchmark.cc "${CMAKE_BINARY_DIR}/tests/smoke.skel.h"
    INCLUDE_DIRECTORIES "${CMAKE_BINARY_DIR}/tests" "${CMAKE_SOURCE_DIR}/tests/pipeline-smoke"
    DEPENDS smoke_skeleton
)

capsule_benchmark(
    lua_benchmark
    SOURCES lua/lua_benchmark.cc "${CMAKE_BINARY_DIR}/tests/lua/lua_runner.skel.h"
    INCLUDE_DIRECTORIES "${CMAKE_BINARY_DIR}/tests/lua" "${CMAKE_SOURCE_DIR}/tests/lua"
    DEPENDS lua_runner_skeleton
)
target_compile_definitions(
    lua_benchmark PRIVATE LUA_BENCH_SCRIPT="${CMAKE_CURRENT_SOURCE_DIR}/lua/script.lua"
)
install(
    FILES "${CMAKE_CURRENT_SOURCE_DIR}/lua/script.lua"
    DESTINATION "${CMAKE_INSTALL_LIBEXECDIR}/bpf-capsule/benchmarks"
    RENAME lua-script.lua
)

capsule_benchmark(
    overhead_benchmark
    SOURCES overhead/overhead_benchmark.cc "${CMAKE_BINARY_DIR}/tests/overhead.skel.h"
    INCLUDE_DIRECTORIES "${CMAKE_BINARY_DIR}/tests" "${CMAKE_SOURCE_DIR}/tests/overhead"
    DEPENDS overhead_skeleton
)
