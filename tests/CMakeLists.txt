# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
# An ordinary consumer of an installed BPF Capsule SDK, built once per target
# profile. Test-specific wrappers add machine verification and GoogleTest
# discovery; every guest object still goes through the public CMake API.
#
#   cmake -S tests -B build/tests -DCMAKE_PREFIX_PATH=/path/to/installed/sdk
cmake_minimum_required(VERSION 3.24)
project(BpfCapsuleTests LANGUAGES C CXX)

include(GNUInstallDirs)
include(FetchContent)
set(CMAKE_C_STANDARD 17)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# The contract scripts drive LLVM's own tools (llvm-as, llvm-dis, llvm-readelf)
# from the same installation the SDK was built against.
find_package(LLVM REQUIRED CONFIG)
find_package(BpfCapsule REQUIRED CONFIG)
if(NOT LLVM_VERSION_MAJOR EQUAL BPF_CAPSULE_LLVM_MAJOR)
    message(FATAL_ERROR "tests need LLVM ${BPF_CAPSULE_LLVM_MAJOR} to match the SDK; found ${LLVM_PACKAGE_VERSION}")
endif()
find_package(GTest REQUIRED)
find_program(CSMITH_EXECUTABLE NAMES csmith REQUIRED)
find_path(CSMITH_INCLUDE_DIR NAMES csmith.h REQUIRED)
enable_testing()

# The lua-xdp integration test compiles that example's runtime from the
# repository checkout beside this directory.
get_filename_component(BPF_CAPSULE_REPOSITORY_DIR "${PROJECT_SOURCE_DIR}/.." ABSOLUTE)
include("${PROJECT_SOURCE_DIR}/CapsuleTests.cmake")

# Tests branch only where a code-generation capability changes the contract.
# Derive those branches from the exact options sent to bpf-capsule-ld instead
# of accepting a second, independently configurable description of the target.
set(test_cpu v3)
if("-mcpu=v4" IN_LIST BPF_CAPSULE_LINK_OPTIONS)
    set(test_cpu v4)
endif()
set(test_has_arena OFF)
if("--memory=arena" IN_LIST BPF_CAPSULE_LINK_OPTIONS)
    set(test_has_arena ON)
endif()
set(test_has_full_atomics OFF)
if("--allocator-lock=atomic" IN_LIST BPF_CAPSULE_LINK_OPTIONS)
    set(test_has_full_atomics ON)
endif()
set(test_has_managed_atomics OFF)
if("--managed-atomics" IN_LIST BPF_CAPSULE_LINK_OPTIONS)
    set(test_has_managed_atomics ON)
endif()

# Compiler transformations have their own unprivileged contract suite.  Each
# case records the complete canonical LLVM IR (or MIR for machine passes)
# before and after one pass, rather than hiding the contract inside a large
# end-to-end object.
add_subdirectory(pass-contracts)

# The install/export surface is a first-class ABI too. Build a tiny external
# C/C++ consumer exclusively through find_package(BpfCapsule), then prove that
# misspelled public-helper arguments are rejected instead of ignored.
find_program(
    BPF_CAPSULE_LLVM_READELF
    NAMES llvm-readelf-${LLVM_VERSION_MAJOR} llvm-readelf
    HINTS "${LLVM_TOOLS_BINARY_DIR}"
    REQUIRED
)
find_program(BPF_CAPSULE_LLVM_AS NAMES llvm-as-${LLVM_VERSION_MAJOR} llvm-as HINTS "${LLVM_TOOLS_BINARY_DIR}" REQUIRED)
find_program(BPF_CAPSULE_LLVM_AR NAMES llvm-ar-${LLVM_VERSION_MAJOR} llvm-ar HINTS "${LLVM_TOOLS_BINARY_DIR}" REQUIRED)
find_program(
    BPF_CAPSULE_LLVM_DIS
    NAMES llvm-dis-${LLVM_VERSION_MAJOR} llvm-dis
    HINTS "${LLVM_TOOLS_BINARY_DIR}"
    REQUIRED
)
find_program(BPF_CAPSULE_LLVM_NM NAMES llvm-nm-${LLVM_VERSION_MAJOR} llvm-nm HINTS "${LLVM_TOOLS_BINARY_DIR}" REQUIRED)
add_test(
    NAME CMakePackage.InstalledConsumer
    COMMAND
        "${CMAKE_COMMAND}" -DPACKAGE_DIR=${BpfCapsule_DIR} -DCONSUMER_SOURCE=${CMAKE_CURRENT_SOURCE_DIR}/cmake-package
        -DWORK=${CMAKE_CURRENT_BINARY_DIR}/cmake-package-contract "-DLINK_OPTIONS=${BPF_CAPSULE_LINK_OPTIONS}"
        -DLLVM_READELF=${BPF_CAPSULE_LLVM_READELF} "-DPROJECT_GENERATOR=${CMAKE_GENERATOR}"
        "-DPROJECT_GENERATOR_PLATFORM=${CMAKE_GENERATOR_PLATFORM}"
        "-DPROJECT_GENERATOR_TOOLSET=${CMAKE_GENERATOR_TOOLSET}" "-DPROJECT_MAKE_PROGRAM=${CMAKE_MAKE_PROGRAM}"
        "-DPROJECT_C_COMPILER=${CMAKE_C_COMPILER}" "-DPROJECT_CXX_COMPILER=${CMAKE_CXX_COMPILER}" -P
        ${CMAKE_CURRENT_SOURCE_DIR}/cmake-package/RunConsumer.cmake
)
set_tests_properties(CMakePackage.InstalledConsumer PROPERTIES LABELS "package-contract;unprivileged" RUN_SERIAL TRUE)

# Static bitcode libraries follow normal archive extraction rules: pull a
# referenced member and its transitive dependencies, but never unrelated code.
add_test(
    NAME Linker.ArchiveExtraction
    COMMAND
        "${CMAKE_COMMAND}" "-DCAPSULE_LD=$<TARGET_FILE:${BPF_CAPSULE_LD_TARGET}>" -DLLVM_AS=${BPF_CAPSULE_LLVM_AS}
        -DLLVM_AR=${BPF_CAPSULE_LLVM_AR} -DLLVM_DIS=${BPF_CAPSULE_LLVM_DIS} -DLLVM_NM=${BPF_CAPSULE_LLVM_NM}
        -DSOURCE_DIR=${CMAKE_CURRENT_SOURCE_DIR}/linker-archive -DWORK=${CMAKE_CURRENT_BINARY_DIR}/linker-archive -P
        ${CMAKE_CURRENT_SOURCE_DIR}/linker-archive/VerifyArchive.cmake
)
set_tests_properties(Linker.ArchiveExtraction PROPERTIES LABELS "linker-contract;unprivileged")

add_test(
    NAME Linker.PlatformMarkers
    COMMAND
        "${CMAKE_COMMAND}" "-DCAPSULE_LD=$<TARGET_FILE:${BPF_CAPSULE_LD_TARGET}>"
        -DSOURCE=${CMAKE_CURRENT_SOURCE_DIR}/linker-archive/markers.ll -DWORK=${CMAKE_CURRENT_BINARY_DIR}/linker-markers
        -P ${CMAKE_CURRENT_SOURCE_DIR}/linker-archive/VerifyMarkers.cmake
)
set_tests_properties(Linker.PlatformMarkers PROPERTIES LABELS "linker-contract;unprivileged")

# A guest must never inherit headers from the host libc merely because the
# host-side CMake project was configured with a native compiler.
add_test(
    NAME Compiler.NoHostLibcHeaders
    COMMAND
        "${CMAKE_COMMAND}" "-DCAPSULE_CC=$<TARGET_FILE:${BPF_CAPSULE_CC_TARGET}>"
        -DSOURCE=${CMAKE_CURRENT_SOURCE_DIR}/compiler/no_host_headers.c
        -DOUTPUT=${CMAKE_CURRENT_BINARY_DIR}/no-host-headers.i -P
        ${CMAKE_CURRENT_SOURCE_DIR}/compiler/VerifyIncludeIsolation.cmake
)
set_tests_properties(Compiler.NoHostLibcHeaders PROPERTIES LABELS "compiler-contract;unprivileged")

set(test_source_dir "${CMAKE_CURRENT_SOURCE_DIR}")

# ============================================================================
# Pipeline: the smallest complete capsule program (recursive fib through the
# software stack), proving cc -> ld -> skeleton -> configure -> load -> run.
# ============================================================================

capsule_test_object(smoke SOURCES pipeline-smoke/smoke_bpf.c INCLUDE_DIRECTORIES ${test_source_dir}/pipeline-smoke)
capsule_gtest_host(
    smoke_test
    SOURCES pipeline-smoke/smoke_test.cc
    SKELETONS smoke_skeleton
    INCLUDE_DIRECTORIES ${test_source_dir}/pipeline-smoke
)

# Source-level adversarial register pressure. The generated function keeps
# 1,200 scalar values live across a late load, so the ordinary BPF allocator
# creates more than 8 KiB of physical spills. This complements the small MIR
# contracts: the complete cc -> ld -> ELF path must relocate that extent into
# the compiler-owned half of the fiber stack without reviving a scratch map.
set(LARGE_PRESSURE_SOURCE "${CMAKE_CURRENT_BINARY_DIR}/spill-contracts/large-pressure.c")
add_custom_command(
    OUTPUT "${LARGE_PRESSURE_SOURCE}"
    COMMAND
        "${CMAKE_COMMAND}" -DOUTPUT=${LARGE_PRESSURE_SOURCE} -DVALUE_COUNT=1200 -P
        "${test_source_dir}/spill-contracts/GeneratePressure.cmake"
    DEPENDS "${test_source_dir}/spill-contracts/GeneratePressure.cmake"
    COMMENT "generate: adversarial physical-spill source"
    VERBATIM
)
capsule_test_object(spill_pressure SOURCES "${LARGE_PRESSURE_SOURCE}")
find_program(
    BPF_CAPSULE_LLVM_OBJDUMP
    NAMES llvm-objdump-${LLVM_VERSION_MAJOR} llvm-objdump
    HINTS "${LLVM_TOOLS_BINARY_DIR}"
    REQUIRED
)
add_test(
    NAME SpillContract.LargePressure
    COMMAND
        "${CMAKE_COMMAND}" -DLLVM_READELF=${BPF_CAPSULE_LLVM_READELF} -DLLVM_OBJDUMP=${BPF_CAPSULE_LLVM_OBJDUMP}
        -DOBJECT=${CMAKE_CURRENT_BINARY_DIR}/spill_pressure.bpf.o -P
        "${test_source_dir}/spill-contracts/VerifyLargePressure.cmake"
)
set_tests_properties(SpillContract.LargePressure PROPERTIES LABELS "spill-contract;unprivileged")

# The post-RA mover is only legal in a generated physical step, which owns a
# leased fiber. A zero experimental budget must leave ordinary entry frames
# native, and a genuinely oversized native frame must fail explicitly.
add_test(
    NAME SpillContract.NativeStackOwnership
    COMMAND
        "${CMAKE_COMMAND}" "-DBPF_CAPSULE_LD=$<TARGET_FILE:${BPF_CAPSULE_LD_TARGET}>"
        -DLLVM_READELF=${BPF_CAPSULE_LLVM_READELF} -DTARGET_CPU=${test_cpu}
        -DSOURCE_DIR=${test_source_dir}/spill-contracts -DWORK=${CMAKE_CURRENT_BINARY_DIR}/spill-contracts/native-stack
        -P "${test_source_dir}/spill-contracts/VerifyNativeStack.cmake"
)
set_tests_properties(SpillContract.NativeStackOwnership PROPERTIES LABELS "spill-contract;unprivileged")

# A BPF helper can read the full declared extent of a native-stack buffer even
# if the generated instructions directly touch only its first byte. Verify
# that post-RA packing keeps that complete range native and disjoint while
# still relocating unrelated scalar pressure into unified fiber memory.
add_test(
    NAME SpillContract.HelperVisibleBuffer
    COMMAND
        "${CMAKE_COMMAND}" "-DBPF_CAPSULE_LD=$<TARGET_FILE:${BPF_CAPSULE_LD_TARGET}>"
        -DLLVM_READELF=${BPF_CAPSULE_LLVM_READELF} -DLLVM_OBJDUMP=${BPF_CAPSULE_LLVM_OBJDUMP} -DTARGET_CPU=${test_cpu}
        -DGENERATOR=${test_source_dir}/spill-contracts/GenerateHelperVisible.cmake
        -DWORK=${CMAKE_CURRENT_BINARY_DIR}/spill-contracts/helper-visible -P
        "${test_source_dir}/spill-contracts/VerifyHelperVisible.cmake"
)
set_tests_properties(SpillContract.HelperVisibleBuffer PROPERTIES LABELS "spill-contract;unprivileged")

# ============================================================================
# Host runtime alone — no BPF, no privilege. Its own binary because it
# interposes bpf_prog_test_run_opts for the whole link unit.
# ============================================================================

capsule_gtest_host(errors_test UNPRIVILEGED SOURCES errors/errors_test.cc)

add_executable(int128_contract_test compiler-runtime/int128_contract.c ${BPF_CAPSULE_COMPILER_RUNTIME_DIR}/int128.c)
target_include_directories(int128_contract_test PRIVATE "${BPF_CAPSULE_INTERNAL_INCLUDE_DIR}")
target_compile_options(int128_contract_test PRIVATE -fno-builtin)
add_test(NAME CompilerRuntime.Int128Contracts COMMAND int128_contract_test)
set_tests_properties(CompilerRuntime.Int128Contracts PROPERTIES LABELS unprivileged)

# ============================================================================
# Runtime semantics: fibers, suspension, memory.
# ============================================================================

# The yield protocol: suspension round-trips, single-use generation-checked
# continuations, host access to a suspended fiber's stack, reset semantics.
capsule_test_object(yield SOURCES yield/yield_bpf.c INCLUDE_DIRECTORIES ${test_source_dir}/yield)
capsule_gtest_host(
    yield_test
    SOURCES yield/yield_test.cc
    SKELETONS yield_skeleton
    INCLUDE_DIRECTORIES ${test_source_dir}/yield
)

# Fiber pool at full scale: pre-load validation, 512-lease exhaustion and
# recycling, a fiber whose stack begins beyond the direct-map prefix.
capsule_test_object(
    fiber_scale
    SOURCES fiber-scale/fiber_scale_bpf.c
    INCLUDE_DIRECTORIES ${test_source_dir}/fiber-scale
)
capsule_gtest_host(
    fiber_scale_test
    SOURCES fiber-scale/fiber_scale_test.cc
    SKELETONS fiber_scale_skeleton
    INCLUDE_DIRECTORIES ${test_source_dir}/fiber-scale
)

# Arena memory: heap sizing grows the backing map, the host-reserved
# prefix, host I/O across region boundaries, invalid-address rejection.
capsule_test_object(memory SOURCES memory/memory_bpf.c INCLUDE_DIRECTORIES ${test_source_dir}/memory)
capsule_gtest_host(
    memory_test
    SOURCES memory/memory_test.cc
    SKELETONS memory_skeleton
    INCLUDE_DIRECTORIES ${test_source_dir}/memory
)

# Runtime atomics: real BPF atomic ISA from concurrent CPUs, and managed
# relaxed load/store staying tearing-free under a writer/reader pair. Profiles
# with managed atomics additionally exercise the complete C atomic surface in
# Capsule memory, through either arena pointers or fixed-map accessors.
set(atomics_definitions)
if(test_has_managed_atomics)
    list(APPEND atomics_definitions BPF_CAPSULE_TEST_MANAGED_RMW=1)
endif()
capsule_test_object(
    atomics
    SOURCES atomics/native_bpf.c
    INCLUDE_DIRECTORIES ${test_source_dir}/atomics
    COMPILE_DEFINITIONS ${atomics_definitions}
)
capsule_gtest_host(
    atomics_test
    SOURCES atomics/atomics_test.cc
    SKELETONS atomics_skeleton
    INCLUDE_DIRECTORIES ${test_source_dir}/atomics
    LIBRARIES pthread
)
if(test_has_managed_atomics)
    target_compile_definitions(atomics_test PRIVATE BPF_CAPSULE_TEST_MANAGED_RMW=1)
endif()

# Arena first-entry initialization under eight simultaneous lanes.
if(test_has_arena)
    capsule_test_object(
        arena_init
        SOURCES arena-init/arena_init_bpf.c
        INCLUDE_DIRECTORIES ${test_source_dir}/arena-init
    )
    capsule_gtest_host(
        arena_init_test
        SOURCES arena-init/arena_init_test.cc
        SKELETONS arena_init_skeleton
        INCLUDE_DIRECTORIES ${test_source_dir}/arena-init
        LIBRARIES pthread
    )
endif()

# ============================================================================
# Compiler semantics: the transform's contracts on guest code.
# ============================================================================

# The native_contract chain runs natively, and flattening it
# retires the unreachable original API.
capsule_test_object(nosuspend SOURCES nosuspend/nosuspend_bpf.c INCLUDE_DIRECTORIES ${test_source_dir}/nosuspend)
capsule_gtest_host(
    nosuspend_test
    SOURCES nosuspend/nosuspend_test.cc
    SKELETONS nosuspend_skeleton
    INCLUDE_DIRECTORIES ${test_source_dir}/nosuspend
)

# SSA snapshots survive managed calls; demoting loop-carried PHIs tolerates a
# second queued demotion becoming use-empty (both from Lua bugs).
capsule_test_object(rehash SOURCES rehash/rehash_bpf.c INCLUDE_DIRECTORIES ${test_source_dir}/rehash)
capsule_gtest_host(
    rehash_test
    SOURCES rehash/rehash_test.cc
    SKELETONS rehash_skeleton
    INCLUDE_DIRECTORIES ${test_source_dir}/rehash
)

# Helper-returned pointers stay verifier-native and are consumed before the
# region returns; context scalars may cross managed-call boundaries.
capsule_test_object(
    verifier_pointer
    SOURCES verifier-pointer/verifier_pointer_bpf.c
    INCLUDE_DIRECTORIES ${test_source_dir}/verifier-pointer
)
capsule_gtest_host(
    verifier_pointer_test
    SOURCES verifier-pointer/verifier_pointer_test.cc
    SKELETONS verifier_pointer_skeleton
    INCLUDE_DIRECTORIES ${test_source_dir}/verifier-pointer
)

# A hidden verifier context works both directly and after an explicit
# yield/continue pair within the same XDP invocation.
capsule_test_object(
    ctx_borrowed
    SOURCES context-interop/context_interop_borrowed_bpf.c
    INCLUDE_DIRECTORIES ${test_source_dir}/context-interop
)
capsule_test_object(
    ctx_yield
    SOURCES context-interop/context_interop_yield_bpf.c
    INCLUDE_DIRECTORIES ${test_source_dir}/context-interop
)
capsule_gtest_host(
    context_interop_test
    SOURCES context-interop/context_interop_test.cc
    SKELETONS ctx_borrowed_skeleton ctx_yield_skeleton
    INCLUDE_DIRECTORIES ${test_source_dir}/context-interop
)

# The broad integration fixture at drive level 2 with 2 fibers: recursion,
# indirect calls, tail frames, aggregates, guards, aggregate returns across
# suspension, fiber isolation, and the shared TLSF allocator under
# concurrency. Custom geometry, so the runtime compiles with the suite's
# defines.
set(compiler_profile_definitions)
if(test_has_full_atomics)
    list(APPEND compiler_profile_definitions BPF_CAPSULE_TEST_FULL_ATOMICS=1)
endif()
capsule_test_object(
    compiler
    SOURCES compiler/compiler_bpf.c
    INCLUDE_DIRECTORIES ${test_source_dir}/compiler
    COMPILE_DEFINITIONS BPF_CAPSULE_MAX_FIBERS=2 BPF_CAPSULE_DRIVE_LEVEL=2 ${compiler_profile_definitions}
    SYSTEM_COMPILE_DEFINITIONS BPF_CAPSULE_MAX_FIBERS=2 BPF_CAPSULE_DRIVE_LEVEL=2
)
capsule_gtest_host(
    compiler_test
    SOURCES compiler/compiler_test.cc
    SKELETONS compiler_skeleton
    INCLUDE_DIRECTORIES ${test_source_dir}/compiler
    LIBRARIES pthread
)

# Picolibc under the transform: stdio and platform overrides, numeric parsing,
# libm after soft-float lowering, and allocator failure without a heap.
capsule_test_object(libc SOURCES libc/libc_bpf.c INCLUDE_DIRECTORIES ${test_source_dir}/libc)
capsule_gtest_host(
    libc_test
    SOURCES libc/libc_test.cc
    SKELETONS libc_skeleton
    INCLUDE_DIRECTORIES ${test_source_dir}/libc
)

# ============================================================================
# Workloads: a real interpreter end to end.
# ============================================================================

add_subdirectory(lua)
add_subdirectory(csmith)
