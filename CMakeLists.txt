# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
# The BPF Capsule SDK: the two compiler drivers, the pass library they embed,
# the host runtime library, guest runtime sources, Picolibc, and the CMake
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
set(BPF_CAPSULE_INSTALL_COMPILER_RUNTIME_DIR "${BPF_CAPSULE_INSTALL_RUNTIME_DIR}/compiler")
set(BPF_CAPSULE_INSTALL_PLATFORM_DIR "${BPF_CAPSULE_INSTALL_RUNTIME_DIR}/platform")
set(BPF_CAPSULE_INSTALL_LIBC_DIR "${CMAKE_INSTALL_DATADIR}/bpf-capsule/libc")
set(BPF_CAPSULE_INSTALL_SYSROOT_DIR "${CMAKE_INSTALL_DATADIR}/bpf-capsule/sysroot")
set(BPF_CAPSULE_INSTALL_TLSF_DIR "${CMAKE_INSTALL_DATADIR}/bpf-capsule/tlsf")
set(BPF_CAPSULE_INSTALL_RUST_RUNTIME_DIR "${CMAKE_INSTALL_DATADIR}/bpf-capsule/rust/bpf-capsule-rt")

set(CMAKE_C_STANDARD 17)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# TLSF backs the Capsule allocator. Its wrapper supplies Capsule-specific
# assert and printf policy without patching the upstream sources.
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

# A clean guest sysroot contains Picolibc plus Linux UAPI. Locate the three
# include roots separately because distributions commonly keep asm/ in a
# multiarch directory while Nix installs all three together.
find_path(BPF_CAPSULE_LINUX_UAPI_INCLUDE_DIR NAMES linux/bpf.h REQUIRED)
find_path(
    BPF_CAPSULE_LINUX_UAPI_ARCH_INCLUDE_DIR
    NAMES asm/types.h
    PATH_SUFFIXES "${CMAKE_LIBRARY_ARCHITECTURE}"
    REQUIRED
)
find_path(BPF_CAPSULE_LINUX_UAPI_GENERIC_INCLUDE_DIR NAMES asm-generic/types.h REQUIRED)

# Expose only Linux UAPI through the guest sysroot. Symbolic links keep the SDK
# tied to the target headers selected by the toolchain without redistributing
# those headers or admitting unrelated host C-library headers.
set(_bpf_capsule_linux_uapi_overlay "${CMAKE_CURRENT_BINARY_DIR}/linux-uapi")
file(REMOVE_RECURSE "${_bpf_capsule_linux_uapi_overlay}")
file(MAKE_DIRECTORY "${_bpf_capsule_linux_uapi_overlay}")
file(CREATE_LINK "${BPF_CAPSULE_LINUX_UAPI_INCLUDE_DIR}/linux" "${_bpf_capsule_linux_uapi_overlay}/linux" SYMBOLIC)
file(CREATE_LINK "${BPF_CAPSULE_LINUX_UAPI_ARCH_INCLUDE_DIR}/asm" "${_bpf_capsule_linux_uapi_overlay}/asm" SYMBOLIC)
file(
    CREATE_LINK
        "${BPF_CAPSULE_LINUX_UAPI_GENERIC_INCLUDE_DIR}/asm-generic"
        "${_bpf_capsule_linux_uapi_overlay}/asm-generic"
    SYMBOLIC
)

# The cc wrapper can locate this path while building from the source tree.
# Its headers are produced by the Picolibc ExternalProject after cc itself is
# built, avoiding a compiler/library dependency cycle.
set(BPF_CAPSULE_BUILD_GUEST_SYSROOT "${CMAKE_BINARY_DIR}/picolibc")

add_subdirectory(src/pass)
add_subdirectory(tools)
include(cmake/Picolibc.cmake)

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
        BPF_CAPSULE_INSTALL_COMPILER_RUNTIME_DIR
        BPF_CAPSULE_INSTALL_PLATFORM_DIR
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
install(
    DIRECTORY src/runtime/compiler/
    DESTINATION "${BPF_CAPSULE_INSTALL_COMPILER_RUNTIME_DIR}"
    FILES_MATCHING
    PATTERN "*.c"
)
install(DIRECTORY src/runtime/platform/ DESTINATION "${BPF_CAPSULE_INSTALL_PLATFORM_DIR}" FILES_MATCHING PATTERN "*.c")
install(FILES "${BPF_CAPSULE_LIBC_ARCHIVE}" DESTINATION "${BPF_CAPSULE_INSTALL_LIBC_DIR}")
# Picolibc is configured and installed by an ExternalProject, so its generated
# headers appear only at build time. Assemble the final guest sysroot during
# the SDK install and let the Capsule setjmp ABI replace the target-less one.
install(
    DIRECTORY "${BPF_CAPSULE_LIBC_INCLUDE_DIR}/"
    DESTINATION "${BPF_CAPSULE_INSTALL_SYSROOT_DIR}/usr/include"
    PATTERN "setjmp.h" EXCLUDE
)
install(DIRECTORY "${_bpf_capsule_linux_uapi_overlay}/" DESTINATION "${BPF_CAPSULE_INSTALL_SYSROOT_DIR}/usr/include")
install(
    DIRECTORY src/runtime/platform/include/
    DESTINATION "${BPF_CAPSULE_INSTALL_SYSROOT_DIR}/usr/include"
    FILES_MATCHING
    PATTERN "*.h"
)
install(FILES "${tlsf_SOURCE_DIR}/tlsf.c" "${tlsf_SOURCE_DIR}/tlsf.h" DESTINATION "${BPF_CAPSULE_INSTALL_TLSF_DIR}")
install(FILES src/rust/bpf-capsule-rt/Cargo.toml DESTINATION "${BPF_CAPSULE_INSTALL_RUST_RUNTIME_DIR}")
install(
    DIRECTORY src/rust/bpf-capsule-rt/src/
    DESTINATION "${BPF_CAPSULE_INSTALL_RUST_RUNTIME_DIR}/src"
    FILES_MATCHING
    PATTERN "*.rs"
)
install(
    FILES src/rust/compiler-builtins-LICENSE.txt "${picolibc_SOURCE_DIR}/COPYING.picolibc"
    DESTINATION "${CMAKE_INSTALL_DATADIR}/licenses/bpf-capsule"
)
install(FILES LICENSE DESTINATION "${CMAKE_INSTALL_DATADIR}/licenses/bpf-capsule")
install(FILES README.md DESIGN.md PLATFORM.md DESTINATION "${CMAKE_INSTALL_DOCDIR}")
