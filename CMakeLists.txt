# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
# The BPF Capsule SDK: the two compiler drivers, the pass library they embed,
# the host runtime library, the guest runtime and libc sources, and the CMake
# integration installed for consumers. Nothing here depends on a target
# kernel. Everything that does — tests, benchmarks, examples — is a separate
# CMake project that consumes an installed SDK through find_package(BpfCapsule).
cmake_minimum_required(VERSION 3.24)
project(BpfCapsule VERSION 0.1.0 LANGUAGES C CXX)

include(CMakePackageConfigHelpers)
include(FetchContent)
include(GNUInstallDirs)

set(BPF_CAPSULE_INSTALL_CMAKE_DIR "${CMAKE_INSTALL_LIBDIR}/cmake/BpfCapsule")
set(BPF_CAPSULE_INSTALL_INCLUDE_DIR "${CMAKE_INSTALL_INCLUDEDIR}/bpf-capsule")
set(BPF_CAPSULE_INSTALL_INTERNAL_INCLUDE_DIR "${BPF_CAPSULE_INSTALL_INCLUDE_DIR}/internal")
set(BPF_CAPSULE_INSTALL_RUNTIME_DIR "${CMAKE_INSTALL_DATADIR}/bpf-capsule/runtime")
set(BPF_CAPSULE_INSTALL_LIBC_DIR "${CMAKE_INSTALL_DATADIR}/bpf-capsule/libc")
set(BPF_CAPSULE_INSTALL_TLSF_DIR "${CMAKE_INSTALL_DATADIR}/bpf-capsule/tlsf")
set(BPF_CAPSULE_INSTALL_RUST_RUNTIME_DIR "${CMAKE_INSTALL_DATADIR}/bpf-capsule/rust/bpf-capsule-rt")

set(CMAKE_C_STANDARD 17)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# TLSF is compiled as part of the guest libc. Capsule's wrapper supplies its
# freestanding assert and printf policy without patching the upstream sources.
FetchContent_Declare(
    tlsf
    URL https://github.com/mattconte/tlsf/archive/deff9ab509341f264addbd3c8ada533678591905.tar.gz
    URL_HASH SHA256=df67543d45ad5e67d96168b54022a0f4803f8d5ae9770d398e20dd9a0e2934d6
)
FetchContent_MakeAvailable(tlsf)

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
    HINTS "${CLANG_INSTALL_PREFIX}/bin" "${LLVM_TOOLS_BINARY_DIR}"
    REQUIRED
)
message(STATUS "BPF Capsule LLVM ${LLVM_PACKAGE_VERSION}, clang: ${BPF_CAPSULE_CLANG}")

find_package(PkgConfig REQUIRED)
pkg_check_modules(LibBpf libbpf>=1.4.0 REQUIRED IMPORTED_TARGET)

add_subdirectory(src/pass)
add_subdirectory(tools)

add_library(bpf_capsule_host STATIC src/runtime/host/bpf_capsule_host.c)
target_include_directories(
    bpf_capsule_host
    PUBLIC
        $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/src/runtime>
        $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/src/runtime/host>
        $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/src/runtime/guest>
        $<INSTALL_INTERFACE:${BPF_CAPSULE_INSTALL_INCLUDE_DIR}>
)
target_include_directories(bpf_capsule_host PRIVATE "${PROJECT_SOURCE_DIR}/src/runtime/internal")
target_link_libraries(bpf_capsule_host PUBLIC PkgConfig::LibBpf)
set_target_properties(bpf_capsule_host PROPERTIES EXPORT_NAME host)

configure_package_config_file(
    cmake/BpfCapsuleConfig.cmake.in
    "${CMAKE_CURRENT_BINARY_DIR}/BpfCapsuleConfig.cmake"
    INSTALL_DESTINATION "${BPF_CAPSULE_INSTALL_CMAKE_DIR}"
    PATH_VARS
        BPF_CAPSULE_INSTALL_INCLUDE_DIR
        BPF_CAPSULE_INSTALL_INTERNAL_INCLUDE_DIR
        BPF_CAPSULE_INSTALL_RUNTIME_DIR
        BPF_CAPSULE_INSTALL_LIBC_DIR
        BPF_CAPSULE_INSTALL_TLSF_DIR
        BPF_CAPSULE_INSTALL_RUST_RUNTIME_DIR
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
    DESTINATION "${BPF_CAPSULE_INSTALL_CMAKE_DIR}"
)
install(TARGETS bpf_capsule_host EXPORT BpfCapsuleTargets ARCHIVE DESTINATION "${CMAKE_INSTALL_LIBDIR}")
install(
    FILES
        cmake/BpfCapsule.cmake
        cmake/GenerateSkeleton.cmake
        cmake/BuildRustBitcode.cmake
        "${CMAKE_CURRENT_BINARY_DIR}/BpfCapsuleConfig.cmake"
        "${CMAKE_CURRENT_BINARY_DIR}/BpfCapsuleConfigVersion.cmake"
    DESTINATION "${BPF_CAPSULE_INSTALL_CMAKE_DIR}"
)
install(
    FILES src/runtime/guest/bpf_capsule.h src/runtime/guest/bpf_capsule_types.h src/runtime/host/bpf_capsule_host.h
    DESTINATION "${BPF_CAPSULE_INSTALL_INCLUDE_DIR}"
)
install(
    DIRECTORY src/runtime/internal/
    DESTINATION "${BPF_CAPSULE_INSTALL_INTERNAL_INCLUDE_DIR}"
    FILES_MATCHING
    PATTERN "*.h"
)
install(FILES src/runtime/guest/bpf_capsule.c DESTINATION "${BPF_CAPSULE_INSTALL_RUNTIME_DIR}")
install(DIRECTORY src/libc/ DESTINATION "${BPF_CAPSULE_INSTALL_LIBC_DIR}" FILES_MATCHING PATTERN "*.c" PATTERN "*.h")
install(FILES "${tlsf_SOURCE_DIR}/tlsf.c" "${tlsf_SOURCE_DIR}/tlsf.h" DESTINATION "${BPF_CAPSULE_INSTALL_TLSF_DIR}")
install(FILES src/rust/bpf-capsule-rt/Cargo.toml DESTINATION "${BPF_CAPSULE_INSTALL_RUST_RUNTIME_DIR}")
install(
    DIRECTORY src/rust/bpf-capsule-rt/src/
    DESTINATION "${BPF_CAPSULE_INSTALL_RUST_RUNTIME_DIR}/src"
    FILES_MATCHING
    PATTERN "*.rs"
)
install(FILES src/rust/compiler-builtins-LICENSE.txt DESTINATION "${CMAKE_INSTALL_DATADIR}/licenses/bpf-capsule")
install(FILES LICENSE DESTINATION "${CMAKE_INSTALL_DATADIR}/licenses/bpf-capsule")
install(FILES README.md DESIGN.md DESTINATION "${CMAKE_INSTALL_DOCDIR}")
