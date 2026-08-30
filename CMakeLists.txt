# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
# Build the two-tool compiler, its runtime and, when requested, the same
# downstream-style tests used by an embedding project.
cmake_minimum_required(VERSION 3.21)
project(
    BpfCapsule
    VERSION 0.1.0
    LANGUAGES C CXX
)

include(CMakePackageConfigHelpers)
include(GNUInstallDirs)

set(CMAKE_C_STANDARD 17)
set(CMAKE_CXX_STANDARD 20)

# One LLVM installation supplies the pass library's headers and the clang the
# cc wrapper defaults to. LLVMConfig.cmake is authoritative for location and
# version; 23 is required (first release whose BPF backend emits an indirect
# jump the kernel verifier accepts). The major is asserted explicitly because
# LLVM's config-version file refuses partial matches against pre-release
# builds ("23" vs "23.1.0-rc1").
find_package(LLVM REQUIRED CONFIG)
if(NOT LLVM_VERSION_MAJOR EQUAL 23)
    message(FATAL_ERROR "BPF Capsule requires LLVM 23; found ${LLVM_PACKAGE_VERSION} at ${LLVM_DIR}")
endif()
# ClangConfig performs its own nested LLVM lookup. Some packaged configs do
# not propagate the first lookup's ordinary (non-cache) compile variables back
# through that package scope. Capture the LLVM C++ contract before discovering
# Clang so a subsequent CMake regeneration cannot silently drop the headers or
# collapse LLVM's space-separated definitions into one malformed -D argument.
set(BPF_CAPSULE_LLVM_INCLUDE_DIRS ${LLVM_INCLUDE_DIRS})
separate_arguments(BPF_CAPSULE_LLVM_DEFINITIONS NATIVE_COMMAND "${LLVM_DEFINITIONS}")
find_package(Clang ${LLVM_VERSION_MAJOR}.${LLVM_VERSION_MINOR} REQUIRED CONFIG)
find_program(
    BPF_CAPSULE_CLANG
    NAMES clang-${LLVM_VERSION_MAJOR} clang
    HINTS "${CLANG_INSTALL_PREFIX}/bin" "${LLVM_TOOLS_BINARY_DIR}" REQUIRED
)
message(STATUS "BPF Capsule LLVM ${LLVM_PACKAGE_VERSION}, clang: ${BPF_CAPSULE_CLANG}")
set(BPF_CAPSULE_LLVM_MAJOR "${LLVM_VERSION_MAJOR}")

option(BPF_CAPSULE_BUILD_TESTS "Build the compiler and runtime tests" ON)
option(BPF_CAPSULE_BUILD_BENCHMARKS "Build benchmarks" ON)
option(BPF_CAPSULE_BUILD_LUA_TEST "Build the full Lua interpreter integration tests" ON)
option(BPF_CAPSULE_BUILD_EXAMPLES "Build library and language examples" OFF)
option(BPF_CAPSULE_INSTALL_TEST_ARTIFACTS
    "Install proof binaries, benchmarks, and raw workload objects" OFF)
option(BPF_CAPSULE_GUEST_LINE_INFO "Compile large guest libraries with line tables" OFF)
set(BPF_CAPSULE_CSMITH_CASE "" CACHE FILEPATH
    "Generated Csmith source for the optional differential test")
set(BPF_CAPSULE_CSMITH_INCLUDE_DIR "" CACHE PATH
    "Directory containing csmith.h for BPF_CAPSULE_CSMITH_CASE")
set(BPF_CAPSULE_EXAMPLES "all" CACHE STRING
    "Semicolon-separated examples to build, or 'all'")
if(BPF_CAPSULE_GUEST_LINE_INFO)
    set(BPF_CAPSULE_GUEST_DEBUG_FLAG -gline-tables-only)
else()
    set(BPF_CAPSULE_GUEST_DEBUG_FLAG -g0)
endif()
if(BPF_CAPSULE_BUILD_BENCHMARKS AND NOT BPF_CAPSULE_BUILD_TESTS)
    message(FATAL_ERROR "BPF_CAPSULE_BUILD_BENCHMARKS requires BPF_CAPSULE_BUILD_TESTS")
endif()
if(BPF_CAPSULE_BUILD_BENCHMARKS AND NOT BPF_CAPSULE_BUILD_LUA_TEST)
    message(FATAL_ERROR "BPF_CAPSULE_BUILD_BENCHMARKS requires BPF_CAPSULE_BUILD_LUA_TEST")
endif()
if(BPF_CAPSULE_CSMITH_CASE AND NOT BPF_CAPSULE_CSMITH_INCLUDE_DIR)
    message(FATAL_ERROR "BPF_CAPSULE_CSMITH_CASE requires BPF_CAPSULE_CSMITH_INCLUDE_DIR")
endif()
if(BPF_CAPSULE_CSMITH_INCLUDE_DIR AND NOT BPF_CAPSULE_CSMITH_CASE)
    message(FATAL_ERROR "BPF_CAPSULE_CSMITH_INCLUDE_DIR requires BPF_CAPSULE_CSMITH_CASE")
endif()

# The one compatibility choice for the objects this tree builds and tests.
set(BPF_CAPSULE_TARGET_KERNEL
    "6.9"
    CACHE STRING "Oldest Linux kernel the test objects must load on"
)
if(BPF_CAPSULE_TARGET_KERNEL VERSION_GREATER_EQUAL "6.9")
    set(BPF_CAPSULE_HAS_ARENA TRUE)
else()
    set(BPF_CAPSULE_HAS_ARENA FALSE)
endif()

find_package(PkgConfig REQUIRED)
pkg_check_modules(LibBpf libbpf>=1.4.0 REQUIRED IMPORTED_TARGET)
if(BPF_CAPSULE_BUILD_TESTS OR BPF_CAPSULE_BUILD_BENCHMARKS OR BPF_CAPSULE_BUILD_EXAMPLES)
    find_program(BPF_CAPSULE_BPFTOOL NAMES bpftool REQUIRED)
endif()
if(BPF_CAPSULE_BUILD_TESTS)
    find_package(GTest REQUIRED)
    enable_testing()
endif()
if(BPF_CAPSULE_BUILD_BENCHMARKS)
    find_package(benchmark REQUIRED)
endif()

add_subdirectory(src/pass)
add_subdirectory(tools)
add_library(bpf_capsule_host STATIC src/runtime/host/bpf_capsule_host.c)
target_include_directories(bpf_capsule_host
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/src/runtime>
        $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/src/runtime/host>
        $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/src/runtime/guest>
        $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}/bpf-capsule>)
target_include_directories(bpf_capsule_host PRIVATE
    "${CMAKE_SOURCE_DIR}/src/runtime/internal")
target_link_libraries(bpf_capsule_host PUBLIC PkgConfig::LibBpf)
set_target_properties(bpf_capsule_host PROPERTIES EXPORT_NAME host)
set(BPF_CAPSULE_CC_TARGET bpf-capsule-cc)
set(BPF_CAPSULE_LD_TARGET bpf-capsule-ld)
set(BPF_CAPSULE_HOST_TARGET bpf_capsule_host)
set(BPF_CAPSULE_LIBBPF_TARGET PkgConfig::LibBpf)
set(BPF_CAPSULE_INCLUDE_DIRS
    "${CMAKE_SOURCE_DIR}/src/runtime/guest"
    "${CMAKE_SOURCE_DIR}/src/runtime/host")
set(BPF_CAPSULE_RUST_RUNTIME_DIR
    "${CMAKE_SOURCE_DIR}/src/rust/bpf-capsule-rt")
include("${CMAKE_SOURCE_DIR}/cmake/BpfCapsule.cmake")
if(BPF_CAPSULE_BUILD_TESTS)
    add_subdirectory(tests)
endif()
if(BPF_CAPSULE_BUILD_BENCHMARKS)
    add_subdirectory(benchmarks)
endif()
if(BPF_CAPSULE_BUILD_EXAMPLES)
    add_subdirectory(examples)
endif()

configure_package_config_file(
    cmake/BpfCapsuleConfig.cmake.in "${CMAKE_CURRENT_BINARY_DIR}/BpfCapsuleConfig.cmake"
    INSTALL_DESTINATION "${CMAKE_INSTALL_LIBDIR}/cmake/BpfCapsule"
    PATH_VARS CMAKE_INSTALL_INCLUDEDIR CMAKE_INSTALL_DATADIR
)
write_basic_package_version_file(
    "${CMAKE_CURRENT_BINARY_DIR}/BpfCapsuleConfigVersion.cmake"
    VERSION ${PROJECT_VERSION}
    COMPATIBILITY SameMajorVersion
)

install(
    EXPORT BpfCapsuleTargets
    FILE BpfCapsuleTargets.cmake
    NAMESPACE BpfCapsule::
    DESTINATION "${CMAKE_INSTALL_LIBDIR}/cmake/BpfCapsule"
)
install(TARGETS bpf_capsule_host EXPORT BpfCapsuleTargets
        ARCHIVE DESTINATION "${CMAKE_INSTALL_LIBDIR}")
install(
    FILES cmake/BpfCapsule.cmake cmake/GenerateSkeleton.cmake
          cmake/BuildRustBitcode.cmake
          "${CMAKE_CURRENT_BINARY_DIR}/BpfCapsuleConfig.cmake"
          "${CMAKE_CURRENT_BINARY_DIR}/BpfCapsuleConfigVersion.cmake"
    DESTINATION "${CMAKE_INSTALL_LIBDIR}/cmake/BpfCapsule"
)
install(FILES
        src/runtime/guest/bpf_capsule.h
        src/runtime/guest/bpf_capsule_types.h
        src/runtime/host/bpf_capsule_host.h
        DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/bpf-capsule")
install(DIRECTORY src/runtime/internal/
        DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/bpf-capsule/internal"
        FILES_MATCHING PATTERN "*.h")
install(FILES src/runtime/guest/bpf_capsule.c
        DESTINATION "${CMAKE_INSTALL_DATADIR}/bpf-capsule/runtime")
install(DIRECTORY src/libc/ DESTINATION "${CMAKE_INSTALL_DATADIR}/bpf-capsule/libc"
        FILES_MATCHING PATTERN "*.c" PATTERN "*.h")
install(DIRECTORY thirdparty/tlsf/ DESTINATION "${CMAKE_INSTALL_DATADIR}/bpf-capsule/thirdparty/tlsf"
        FILES_MATCHING PATTERN "*.c" PATTERN "*.h" PATTERN "LICENSE")
install(FILES src/rust/bpf-capsule-rt/Cargo.toml
        DESTINATION "${CMAKE_INSTALL_DATADIR}/bpf-capsule/rust/bpf-capsule-rt")
install(DIRECTORY src/rust/bpf-capsule-rt/src/
        DESTINATION "${CMAKE_INSTALL_DATADIR}/bpf-capsule/rust/bpf-capsule-rt/src"
        FILES_MATCHING PATTERN "*.rs")
install(FILES src/rust/compiler-builtins-LICENSE.txt
        DESTINATION "${CMAKE_INSTALL_DATADIR}/licenses/bpf-capsule")
install(FILES LICENSE
        DESTINATION "${CMAKE_INSTALL_DATADIR}/licenses/bpf-capsule")
install(FILES README.md DESIGN.md
        DESTINATION "${CMAKE_INSTALL_DOCDIR}")
