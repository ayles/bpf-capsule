# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
# Standalone Google Benchmark consumer of an installed BPF Capsule SDK.
#
#   cmake -S benchmarks -B build/benchmarks \
#       -DCMAKE_PREFIX_PATH=/path/to/installed/sdk
cmake_minimum_required(VERSION 3.24)
project(BpfCapsuleBenchmarks LANGUAGES C CXX)

include(GNUInstallDirs)
include(FetchContent)
set(CMAKE_C_STANDARD 17)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(BpfCapsule REQUIRED CONFIG)
find_package(benchmark REQUIRED)
enable_testing()

function(capsule_benchmark name)
    cmake_parse_arguments(ARG "" "" "SOURCES;INCLUDE_DIRECTORIES;SKELETONS" ${ARGN})
    if(ARG_UNPARSED_ARGUMENTS)
        message(FATAL_ERROR "capsule_benchmark(${name}) received unknown arguments: ${ARG_UNPARSED_ARGUMENTS}")
    endif()
    if(NOT ARG_SOURCES OR NOT ARG_SKELETONS)
        message(FATAL_ERROR "capsule_benchmark(${name}) needs SOURCES and SKELETONS")
    endif()

    add_executable(${name} ${ARG_SOURCES})
    target_include_directories(${name} PRIVATE "${PROJECT_SOURCE_DIR}/support" ${ARG_INCLUDE_DIRECTORIES})
    target_link_libraries(${name} PRIVATE benchmark::benchmark BpfCapsule::host ${ARG_SKELETONS})
    add_test(
        NAME ${name}
        COMMAND
            ${name} --benchmark_min_time=0.2s --benchmark_out=${PROJECT_BINARY_DIR}/benchmark-results/${name}.json
            --benchmark_out_format=json
    )
    set_tests_properties(${name} PROPERTIES LABELS "bench;privileged")
    install(TARGETS ${name} RUNTIME DESTINATION "${CMAKE_INSTALL_LIBEXECDIR}/bpf-capsule/benchmarks")
endfunction()

file(MAKE_DIRECTORY "${PROJECT_BINARY_DIR}/benchmark-results")

bpf_capsule_object(
    smoke_bpf
    OUTPUT smoke.bpf.o
    SOURCES pipeline-smoke/smoke_bpf.c
    INCLUDE_DIRECTORIES "${PROJECT_SOURCE_DIR}/pipeline-smoke"
    COMPILE_OPTIONS -g
    LINK_OPTIONS ${BPF_CAPSULE_LINK_OPTIONS}
)
bpf_capsule_skeleton(smoke_skeleton OUTPUT smoke.skel.h OBJECT "${smoke_bpf}" NAME smoke)
capsule_benchmark(
    smoke_benchmark
    SOURCES pipeline-smoke/smoke_benchmark.cc
    INCLUDE_DIRECTORIES "${PROJECT_SOURCE_DIR}/pipeline-smoke"
    SKELETONS smoke_skeleton
)

FetchContent_Declare(
    lua
    URL https://www.lua.org/ftp/lua-5.5.1.tar.gz
    URL_HASH SHA256=1c4b4068d67061f2a2231ad2b5422e77acea1487ea9890f6320af614f4373dce
)
FetchContent_MakeAvailable(lua)
file(GLOB LUA_BPF_SOURCES "${lua_SOURCE_DIR}/src/*.c")
list(FILTER LUA_BPF_SOURCES EXCLUDE REGEX "/(lua|luac)\\.c$")
bpf_capsule_object(
    lua_runner_bpf
    OUTPUT lua_runner.bpf.o
    SOURCES lua/lua_bpf.c ${LUA_BPF_SOURCES}
    INCLUDE_DIRECTORIES "${PROJECT_SOURCE_DIR}/lua" "${lua_SOURCE_DIR}/src"
    COMPILE_DEFINITIONS LUA_USE_JUMPTABLE=0
    COMPILE_OPTIONS -g -include "${PROJECT_SOURCE_DIR}/lua/lua_capsule_config.h"
    LINK_OPTIONS ${BPF_CAPSULE_LINK_OPTIONS}
)
bpf_capsule_skeleton(lua_runner_skeleton OUTPUT lua_runner.skel.h OBJECT "${lua_runner_bpf}" NAME lua_runner)
capsule_benchmark(
    lua_benchmark
    SOURCES lua/lua_benchmark.cc
    INCLUDE_DIRECTORIES "${PROJECT_SOURCE_DIR}/lua"
    SKELETONS lua_runner_skeleton
)
target_compile_definitions(lua_benchmark PRIVATE LUA_BENCH_SCRIPT="${PROJECT_SOURCE_DIR}/lua/script.lua")
install(
    FILES "${PROJECT_SOURCE_DIR}/lua/script.lua"
    DESTINATION "${CMAKE_INSTALL_LIBEXECDIR}/bpf-capsule/benchmarks"
    RENAME lua-script.lua
)

bpf_capsule_object(
    overhead_bpf
    OUTPUT overhead.bpf.o
    SOURCES overhead/overhead_bpf.c
    INCLUDE_DIRECTORIES "${PROJECT_SOURCE_DIR}/overhead"
    COMPILE_OPTIONS -g
    LINK_OPTIONS ${BPF_CAPSULE_LINK_OPTIONS}
)
bpf_capsule_skeleton(overhead_skeleton OUTPUT overhead.skel.h OBJECT "${overhead_bpf}" NAME overhead)
capsule_benchmark(
    overhead_benchmark
    SOURCES overhead/overhead_benchmark.cc
    INCLUDE_DIRECTORIES "${PROJECT_SOURCE_DIR}/overhead"
    SKELETONS overhead_skeleton
)

bpf_capsule_object(
    memcpy_bpf
    OUTPUT memcpy.bpf.o
    SOURCES memcpy/memcpy_bpf.c
    INCLUDE_DIRECTORIES "${PROJECT_SOURCE_DIR}/memcpy"
    COMPILE_OPTIONS -g
    LINK_OPTIONS ${BPF_CAPSULE_LINK_OPTIONS}
)
bpf_capsule_skeleton(memcpy_skeleton OUTPUT memcpy.skel.h OBJECT "${memcpy_bpf}" NAME memcpy)
capsule_benchmark(
    memcpy_benchmark
    SOURCES memcpy/memcpy_benchmark.cc
    INCLUDE_DIRECTORIES "${PROJECT_SOURCE_DIR}/memcpy"
    SKELETONS memcpy_skeleton
)
