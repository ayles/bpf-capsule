# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
cmake_minimum_required(VERSION 3.21)
project(
    BpfCapsule
    VERSION 0.1.0
    LANGUAGES C CXX
)

include(CMakePackageConfigHelpers)

if(CMAKE_EXPORT_COMPILE_COMMANDS)
    set(CMAKE_C_STANDARD_INCLUDE_DIRECTORIES ${CMAKE_C_IMPLICIT_INCLUDE_DIRECTORIES})
    set(CMAKE_CXX_STANDARD_INCLUDE_DIRECTORIES ${CMAKE_CXX_IMPLICIT_INCLUDE_DIRECTORIES})
endif()

set(CMAKE_C_STANDARD 17)
set(CMAKE_CXX_STANDARD 20)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")
include(BpfCapsule)

option(BPF_CAPSULE_BUILD_EXAMPLES "Build library and language examples" OFF)
option(BPF_CAPSULE_BUILD_TESTS "Build the focused compiler and runtime tests" OFF)
option(BPF_CAPSULE_INSTALL_TEST_ARTIFACTS
       "Install raw BPF objects consumed by the regression matrix" OFF
)
set(BPF_CAPSULE_EXAMPLES
    "all"
    CACHE STRING "Semicolon-separated examples to build, or 'all'"
)
set(BPF_CAPSULE_CSMITH_CASE
    ""
    CACHE FILEPATH "Generated csmith source to compile as an optional differential test"
)
set(BPF_CAPSULE_CSMITH_INCLUDE_DIR
    ""
    CACHE PATH "Directory containing csmith.h for BPF_CAPSULE_CSMITH_CASE"
)

if(BPF_CAPSULE_BUILD_EXAMPLES OR BPF_CAPSULE_BUILD_TESTS)
    find_package(PkgConfig REQUIRED)
    pkg_check_modules(LibBpf libbpf>=1.4.0 REQUIRED IMPORTED_TARGET)
    set(BPF_CAPSULE_LIBBPF_TARGET PkgConfig::LibBpf)
endif()

add_subdirectory(src)

if(BPF_CAPSULE_BUILD_EXAMPLES)
    add_subdirectory(examples)
    if(TARGET lua_xdp_skeleton)
        add_subdirectory(tests/lua-xdp)
        add_subdirectory(benchmarks/lua-xdp)
    endif()
    if("all" IN_LIST BPF_CAPSULE_EXAMPLES)
        add_subdirectory(benchmarks/overhead)
    endif()
endif()

if(BPF_CAPSULE_BUILD_TESTS OR (BPF_CAPSULE_BUILD_EXAMPLES AND "all" IN_LIST BPF_CAPSULE_EXAMPLES))
    add_subdirectory(tests/atomics)
    add_subdirectory(tests/arena-init)
    add_subdirectory(tests/context-interop)
    add_subdirectory(tests/fiber-scale)
    add_subdirectory(tests/memory)
    add_subdirectory(tests/rehash)
    add_subdirectory(tests/nosuspend)
    add_subdirectory(tests/verifier-pointer)
    add_subdirectory(tests/yield)
    add_subdirectory(tests/spill-concurrency)
    add_subdirectory(tests/errors)
    add_subdirectory(tests/integration)
    add_subdirectory(tests/libc)
    add_subdirectory(tests/verifier-metrics)
    if(BPF_CAPSULE_CSMITH_CASE)
        if(NOT BPF_CAPSULE_CSMITH_INCLUDE_DIR)
            message(FATAL_ERROR "BPF_CAPSULE_CSMITH_CASE requires BPF_CAPSULE_CSMITH_INCLUDE_DIR")
        endif()
        add_subdirectory(tests/csmith)
    endif()
endif()

configure_package_config_file(
    cmake/BpfCapsuleConfig.cmake.in "${CMAKE_CURRENT_BINARY_DIR}/BpfCapsuleConfig.cmake"
    INSTALL_DESTINATION lib/cmake/BpfCapsule
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
    DESTINATION lib/cmake/BpfCapsule
)
install(
    FILES cmake/BpfCapsule.cmake cmake/BuildRustBitcode.cmake cmake/ExtractRustBitcode.cmake
          cmake/GenerateSkeleton.cmake "${CMAKE_CURRENT_BINARY_DIR}/BpfCapsuleConfig.cmake"
          "${CMAKE_CURRENT_BINARY_DIR}/BpfCapsuleConfigVersion.cmake"
    DESTINATION lib/cmake/BpfCapsule
)
install(DIRECTORY src/libc/ DESTINATION share/bpf-capsule/libc)
install(
    DIRECTORY src/rust/bpf-capsule-rt/
    DESTINATION share/bpf-capsule/rust/bpf-capsule-rt
    PATTERN target EXCLUDE
)
install(FILES LICENSE DESTINATION share/licenses/bpf-capsule)
install(FILES src/rust/compiler-builtins-LICENSE.txt DESTINATION share/licenses/bpf-capsule)
install(FILES README.md DESIGN.md ARCHITECTURE.md SPEC.md CONTRIBUTING.md NOTICE
        DESTINATION share/doc/bpf-capsule
)
install(
    DIRECTORY docs/
    DESTINATION share/doc/bpf-capsule
    FILES_MATCHING
    PATTERN "*.md"
)
