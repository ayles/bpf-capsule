# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
# The test matrix. One suite = one BPF object (capsule_bpf_object: guest
# sources -> .bpf object -> skeleton) plus one gtest host binary
# (capsule_gtest_host); both helpers live in cmake/CapsuleTests.cmake. Run
# as the explicit unprivileged and privileged CTest label groups. The Lua
# integrations share a nested directory because they compile one interpreter.
include(FetchContent)
include("${CMAKE_SOURCE_DIR}/cmake/CapsuleTests.cmake")

# Compiler transformations have their own unprivileged contract suite.  Each
# case records the complete canonical LLVM IR (or MIR for machine passes)
# before and after one pass, rather than hiding the contract inside a large
# end-to-end object.
add_subdirectory(pass-contracts)

# The install/export surface is a first-class ABI too. Build a tiny external
# C/C++ consumer exclusively through find_package(BpfCapsule), then prove that
# misspelled public-helper arguments are rejected instead of ignored.
find_program(BPF_CAPSULE_LLVM_READELF
    NAMES llvm-readelf-${LLVM_VERSION_MAJOR} llvm-readelf
    HINTS "${LLVM_TOOLS_BINARY_DIR}" REQUIRED)
add_test(NAME CMakePackage.InstalledConsumer
    COMMAND "${CMAKE_COMMAND}"
        -DPROJECT_BINARY_DIR=${CMAKE_BINARY_DIR}
        -DPROJECT_INSTALL_PREFIX=${CMAKE_INSTALL_PREFIX}
        -DPROJECT_INSTALL_BINDIR=${CMAKE_INSTALL_BINDIR}
        -DCONSUMER_SOURCE=${CMAKE_CURRENT_SOURCE_DIR}/cmake-package
        -DWORK=${CMAKE_CURRENT_BINARY_DIR}/cmake-package-contract
        -DTARGET_KERNEL=${BPF_CAPSULE_TARGET_KERNEL}
        -DLLVM_READELF=${BPF_CAPSULE_LLVM_READELF}
        "-DPROJECT_GENERATOR=${CMAKE_GENERATOR}"
        "-DPROJECT_GENERATOR_PLATFORM=${CMAKE_GENERATOR_PLATFORM}"
        "-DPROJECT_GENERATOR_TOOLSET=${CMAKE_GENERATOR_TOOLSET}"
        "-DPROJECT_MAKE_PROGRAM=${CMAKE_MAKE_PROGRAM}"
        "-DPROJECT_C_COMPILER=${CMAKE_C_COMPILER}"
        "-DPROJECT_CXX_COMPILER=${CMAKE_CXX_COMPILER}"
        -P ${CMAKE_CURRENT_SOURCE_DIR}/cmake-package/RunConsumer.cmake)
set_tests_properties(CMakePackage.InstalledConsumer PROPERTIES
    LABELS "package-contract;unprivileged" RUN_SERIAL TRUE)

set(D "${CMAKE_CURRENT_SOURCE_DIR}")
set(LIBC "${CMAKE_SOURCE_DIR}/src/libc")
set(LIBC_FLAGS -I${LIBC} -I${LIBC}/include)

# ============================================================================
# Pipeline: the smallest complete capsule program (recursive fib through the
# software stack), proving cc -> ld -> skeleton -> configure -> load -> run.
# ============================================================================

capsule_bpf_object(smoke
    SOURCES pipeline-smoke/smoke_bpf.c
    FLAGS -I${D}/pipeline-smoke
)
capsule_gtest_host(smoke_test
    SOURCES pipeline-smoke/smoke_test.cc
    DEPENDS smoke_skeleton
    INCLUDE_DIRECTORIES ${D}/pipeline-smoke
)

# Matched direct-BPF/Capsule microcases used by the overhead benchmark.  This
# is an object target rather than a semantic gtest: the benchmark validates
# every result while separating JIT, dispatch and virtual-memory costs.
capsule_bpf_object(overhead
    SOURCES overhead/overhead_bpf.c
    FLAGS -I${D}/overhead
)

# Source-level adversarial register pressure. The generated function keeps
# 1,200 scalar values live across a late load, so the ordinary BPF allocator
# creates more than 8 KiB of physical spills. This complements the small MIR
# contracts: the complete cc -> ld -> ELF path must relocate that extent into
# the compiler-owned half of the fiber stack without reviving a scratch map.
set(LARGE_PRESSURE_SOURCE "${CMAKE_CURRENT_BINARY_DIR}/spill-contracts/large-pressure.c")
add_custom_command(
    OUTPUT "${LARGE_PRESSURE_SOURCE}"
    COMMAND "${CMAKE_COMMAND}" -DOUTPUT=${LARGE_PRESSURE_SOURCE} -DVALUE_COUNT=1200
            -P "${D}/spill-contracts/GeneratePressure.cmake"
    DEPENDS "${D}/spill-contracts/GeneratePressure.cmake"
    COMMENT "generate: adversarial physical-spill source"
    VERBATIM
)
capsule_bpf_object(spill_pressure
    SOURCES "${LARGE_PRESSURE_SOURCE}"
)
add_custom_target(spill_pressure_contract_object ALL
    DEPENDS "${CMAKE_CURRENT_BINARY_DIR}/spill_pressure_bpf.o")
find_program(BPF_CAPSULE_LLVM_OBJDUMP NAMES llvm-objdump-${LLVM_VERSION_MAJOR} llvm-objdump
    HINTS "${LLVM_TOOLS_BINARY_DIR}" REQUIRED)
add_test(NAME SpillContract.LargePressure
    COMMAND "${CMAKE_COMMAND}"
        -DLLVM_READELF=${BPF_CAPSULE_LLVM_READELF}
        -DLLVM_OBJDUMP=${BPF_CAPSULE_LLVM_OBJDUMP}
        -DOBJECT=${CMAKE_CURRENT_BINARY_DIR}/spill_pressure_bpf.o
        -P "${D}/spill-contracts/VerifyLargePressure.cmake")
set_tests_properties(SpillContract.LargePressure PROPERTIES
    LABELS "spill-contract;unprivileged")

# The post-RA mover is only legal in a generated physical step, which owns a
# leased fiber. A zero experimental budget must leave ordinary entry frames
# native, and a genuinely oversized native frame must fail explicitly.
find_program(BPF_CAPSULE_TEST_LLC NAMES llc-${LLVM_VERSION_MAJOR} llc
    HINTS "${LLVM_TOOLS_BINARY_DIR}" REQUIRED)
add_test(NAME SpillContract.NativeStackOwnership
    COMMAND "${CMAKE_COMMAND}"
        -DLLC=${BPF_CAPSULE_TEST_LLC}
        -DPLUGIN=$<TARGET_FILE:bpf_capsule_pass_contract_plugin>
        -DLLVM_READELF=${BPF_CAPSULE_LLVM_READELF}
        -DTARGET_KERNEL=${BPF_CAPSULE_TARGET_KERNEL}
        -DSOURCE_DIR=${D}/spill-contracts
        -DWORK=${CMAKE_CURRENT_BINARY_DIR}/spill-contracts/native-stack
        -P "${D}/spill-contracts/VerifyNativeStack.cmake")
set_tests_properties(SpillContract.NativeStackOwnership PROPERTIES
    LABELS "spill-contract;unprivileged")

# A BPF helper can read the full declared extent of a native-stack buffer even
# if the generated instructions directly touch only its first byte. Verify
# that post-RA packing keeps that complete range native and disjoint while
# still relocating unrelated scalar pressure into unified fiber memory.
add_test(NAME SpillContract.HelperVisibleBuffer
    COMMAND "${CMAKE_COMMAND}"
        -DLLC=${BPF_CAPSULE_TEST_LLC}
        -DPLUGIN=$<TARGET_FILE:bpf_capsule_pass_contract_plugin>
        -DLLVM_READELF=${BPF_CAPSULE_LLVM_READELF}
        -DLLVM_OBJDUMP=${BPF_CAPSULE_LLVM_OBJDUMP}
        -DTARGET_KERNEL=${BPF_CAPSULE_TARGET_KERNEL}
        -DGENERATOR=${D}/spill-contracts/GenerateHelperVisible.cmake
        -DWORK=${CMAKE_CURRENT_BINARY_DIR}/spill-contracts/helper-visible
        -P "${D}/spill-contracts/VerifyHelperVisible.cmake")
set_tests_properties(SpillContract.HelperVisibleBuffer PROPERTIES
    LABELS "spill-contract;unprivileged")

# ============================================================================
# Host runtime alone — no BPF, no privilege. Its own binary because it
# interposes bpf_prog_test_run_opts for the whole link unit.
# ============================================================================

capsule_gtest_host(errors_test UNPRIVILEGED SOURCES errors/errors_test.cc)

# The compact libm algorithms also have native, kernel-free edge contracts.
# Their guest equivalents below prove the same behavior after soft-float
# lowering; this executable makes algorithm mistakes fail early and directly.
add_executable(math_contract_test libc/math_contract.c ${LIBC}/mathfns.c ${LIBC}/strtod.c)
target_include_directories(math_contract_test PRIVATE
    "${CMAKE_SOURCE_DIR}/src/runtime/guest")
target_compile_options(math_contract_test PRIVATE -fno-builtin)
add_test(NAME Libc.MathContracts COMMAND math_contract_test)
set_tests_properties(Libc.MathContracts PROPERTIES LABELS unprivileged)

add_executable(int128_contract_test libc/int128_contract.c ${LIBC}/int128.c)
target_include_directories(int128_contract_test PRIVATE
    "${CMAKE_SOURCE_DIR}/src/runtime/internal")
target_compile_options(int128_contract_test PRIVATE -fno-builtin)
add_test(NAME Libc.Int128Contracts COMMAND int128_contract_test)
set_tests_properties(Libc.Int128Contracts PROPERTIES LABELS unprivileged)

# ============================================================================
# Runtime semantics: fibers, suspension, memory.
# ============================================================================

# The yield protocol: suspension round-trips, single-use generation-checked
# continuations, host access to a suspended fiber's stack, reset semantics.
capsule_bpf_object(yield
    SOURCES yield/yield_bpf.c
    FLAGS -I${D}/yield
)
capsule_gtest_host(yield_test
    SOURCES yield/yield_test.cc
    DEPENDS yield_skeleton
    INCLUDE_DIRECTORIES ${D}/yield
)

# Fiber pool at full scale: pre-load validation, 512-lease exhaustion and
# recycling, a fiber whose stack begins beyond the direct-map prefix.
capsule_bpf_object(fiber_scale
    SOURCES fiber-scale/fiber_scale_bpf.c
    FLAGS -I${D}/fiber-scale
)
capsule_gtest_host(fiber_scale_test
    SOURCES fiber-scale/fiber_scale_test.cc
    DEPENDS fiber_scale_skeleton
    INCLUDE_DIRECTORIES ${D}/fiber-scale
)

# Arena memory: heap sizing grows the backing map, the host-reserved
# prefix, host I/O across region boundaries, invalid-address rejection.
capsule_bpf_object(memory
    SOURCES memory/memory_bpf.c
    FLAGS -I${D}/memory
)
capsule_gtest_host(memory_test
    SOURCES memory/memory_test.cc
    DEPENDS memory_skeleton
    INCLUDE_DIRECTORIES ${D}/memory
)

# Runtime atomics: real BPF atomic ISA from concurrent CPUs, and managed
# relaxed load/store staying tearing-free under a writer/reader pair.
capsule_bpf_object(atomics
    SOURCES atomics/native_bpf.c
    FLAGS -I${D}/atomics
)
capsule_gtest_host(atomics_test
    SOURCES atomics/atomics_test.cc
    DEPENDS atomics_skeleton
    INCLUDE_DIRECTORIES ${D}/atomics
    LIBRARIES pthread
)

# Arena first-entry initialization under eight simultaneous lanes.
if(BPF_CAPSULE_HAS_ARENA)
    capsule_bpf_object(arena_init
        SOURCES arena-init/arena_init_bpf.c
        FLAGS -I${D}/arena-init
    )
    capsule_gtest_host(arena_init_test
        SOURCES arena-init/arena_init_test.cc
        DEPENDS arena_init_skeleton
        INCLUDE_DIRECTORIES ${D}/arena-init
        LIBRARIES pthread
    )
endif()

# ============================================================================
# Compiler semantics: the transform's contracts on guest code.
# ============================================================================

# The native_contract chain runs natively, and flattening it
# retires the unreachable original API.
capsule_bpf_object(nosuspend
    SOURCES nosuspend/nosuspend_bpf.c
    FLAGS -I${D}/nosuspend
)
capsule_gtest_host(nosuspend_test
    SOURCES nosuspend/nosuspend_test.cc
    DEPENDS nosuspend_skeleton
    INCLUDE_DIRECTORIES ${D}/nosuspend
)

# SSA snapshots survive managed calls; demoting loop-carried PHIs tolerates a
# second queued demotion becoming use-empty (both from Lua bugs).
capsule_bpf_object(rehash
    SOURCES rehash/rehash_bpf.c ${LIBC}/freestanding.c ${BPF_CAPSULE_LIBC_DIR}/tlsf_capsule.c
    FLAGS -I${D}/rehash ${LIBC_FLAGS}
)
capsule_gtest_host(rehash_test
    SOURCES rehash/rehash_test.cc
    DEPENDS rehash_skeleton
    INCLUDE_DIRECTORIES ${D}/rehash
)

# Helper-returned pointers stay verifier-native and are consumed before the
# region returns; context scalars may cross managed-call boundaries.
capsule_bpf_object(verifier_pointer
    SOURCES verifier-pointer/verifier_pointer_bpf.c
    FLAGS -I${D}/verifier-pointer
)
capsule_gtest_host(verifier_pointer_test
    SOURCES verifier-pointer/verifier_pointer_test.cc
    DEPENDS verifier_pointer_skeleton
    INCLUDE_DIRECTORIES ${D}/verifier-pointer
)

# A hidden verifier context works both directly and after an explicit
# yield/continue pair within the same XDP invocation.
capsule_bpf_object(ctx_borrowed
    SOURCES context-interop/context_interop_borrowed_bpf.c
    FLAGS -I${D}/context-interop
)
capsule_bpf_object(ctx_yield
    SOURCES context-interop/context_interop_yield_bpf.c
    FLAGS -I${D}/context-interop
)
capsule_gtest_host(context_interop_test
    SOURCES context-interop/context_interop_test.cc
    DEPENDS ctx_borrowed_skeleton ctx_yield_skeleton
    INCLUDE_DIRECTORIES ${D}/context-interop
)

# The broad integration fixture at drive level 2 with 2 fibers: recursion,
# indirect calls, tail frames, aggregates, guards, aggregate returns across
# suspension, fiber isolation, and the shared TLSF allocator under
# concurrency. Custom geometry, so the runtime compiles with the suite's
# defines.
capsule_bpf_object(compiler
    SOURCES compiler/compiler_bpf.c ${LIBC}/freestanding.c ${BPF_CAPSULE_LIBC_DIR}/tlsf_capsule.c
            ${LIBC}/softfloat.c ${LIBC}/mathfns.c ${LIBC}/strtod.c
    FLAGS -I${D}/compiler ${LIBC_FLAGS} -DBPF_CAPSULE_MAX_FIBERS=2 -DBPF_CAPSULE_DRIVE_LEVEL=2
    RUNTIME_COMPILE_DEFINITIONS BPF_CAPSULE_MAX_FIBERS=2 BPF_CAPSULE_DRIVE_LEVEL=2
)
capsule_gtest_host(compiler_test
    SOURCES compiler/compiler_test.cc
    DEPENDS compiler_skeleton
    INCLUDE_DIRECTORIES ${D}/compiler
    LIBRARIES pthread
)

# Freestanding libc under the transform: printf, strtoull edges, soft-float
# specials, strtod, and allocator failure without a configured heap.
capsule_bpf_object(libc
    SOURCES libc/libc_bpf.c ${LIBC}/freestanding.c ${BPF_CAPSULE_LIBC_DIR}/tlsf_capsule.c
            ${LIBC}/softfloat.c ${LIBC}/mathfns.c ${LIBC}/strtod.c
    FLAGS -I${D}/libc ${LIBC_FLAGS}
)
capsule_gtest_host(libc_test
    SOURCES libc/libc_test.cc
    DEPENDS libc_skeleton
    INCLUDE_DIRECTORIES ${D}/libc
)

# ============================================================================
# Workloads: a real interpreter end to end.
# ============================================================================

if(BPF_CAPSULE_BUILD_LUA_TEST)
    add_subdirectory(lua)
endif()
if(BPF_CAPSULE_CSMITH_CASE)
    add_subdirectory(csmith)
endif()
