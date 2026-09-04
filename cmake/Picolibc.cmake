# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
# Build the embedded C library with the same compiler as Capsule guests.
# It remains an ordinary bitcode archive: bpf-capsule-ld extracts only the
# members referenced by a program and then optimizes them whole-program.
include_guard(GLOBAL)

include(ExternalProject)
include(FetchContent)
find_package(Patch REQUIRED)

FetchContent_Declare(
    picolibc
    URL https://github.com/picolibc/picolibc/archive/refs/tags/1.8.12.tar.gz
    URL_HASH SHA256=910a28f42f67b5b136c6b8793d89876b21aa80ae8406df77644422da6e772e8a
    DOWNLOAD_EXTRACT_TIMESTAMP TRUE
    # Populate without adding Picolibc to the host build. ExternalProject
    # below gives it the BPF compiler instead.
    SOURCE_SUBDIR
    _bpf_capsule_source_only
)
FetchContent_MakeAvailable(picolibc)

# Picolibc's CMake frontend hard-codes ELF init/fini arrays, unlike its Meson
# frontend. Make that setting overridable, then patch a private build-tree copy
# so a Nix-provided source tree remains immutable. Capsule has no CRT arrays;
# Picolibc's ordinary atexit table is the matching supported implementation.
# gersemi: off
FetchContent_Populate(
    picolibc_patched
    URL "${picolibc_SOURCE_DIR}"
    PATCH_COMMAND
        "${Patch_EXECUTABLE}" --quiet --batch --read-only=ignore -p1 -i
        "${CMAKE_CURRENT_LIST_DIR}/patches/picolibc-cmake-config.patch"
)
# gersemi: on

find_program(BPF_CAPSULE_LLVM_AR NAMES llvm-ar-${LLVM_VERSION_MAJOR} llvm-ar HINTS "${LLVM_TOOLS_BINARY_DIR}" REQUIRED)
find_program(
    BPF_CAPSULE_LLVM_RANLIB
    NAMES llvm-ranlib-${LLVM_VERSION_MAJOR} llvm-ranlib
    HINTS "${LLVM_TOOLS_BINARY_DIR}"
    REQUIRED
)

set(_bpf_capsule_picolibc_build "${CMAKE_BINARY_DIR}/picolibc-build")
set(_bpf_capsule_picolibc_prefix "${BPF_CAPSULE_BUILD_GUEST_SYSROOT}")
set(BPF_CAPSULE_LIBC_ARCHIVE "${_bpf_capsule_picolibc_prefix}/usr/lib/libc.a")
set(BPF_CAPSULE_LIBC_INCLUDE_DIR "${_bpf_capsule_picolibc_prefix}/usr/include")
set(BPF_CAPSULE_LIBC_TARGET bpf_capsule_picolibc)

ExternalProject_Add(
    bpf_capsule_picolibc
    DEPENDS bpf-capsule-cc
    SOURCE_DIR "${picolibc_patched_SOURCE_DIR}"
    BINARY_DIR "${_bpf_capsule_picolibc_build}"
    INSTALL_DIR "${_bpf_capsule_picolibc_prefix}"
    CMAKE_ARGS
        "-DCMAKE_INSTALL_PREFIX:PATH=<INSTALL_DIR>/usr" "-DCMAKE_BUILD_TYPE:STRING=Release"
        "-DCMAKE_SYSTEM_NAME:STRING=Generic" "-DCMAKE_SYSTEM_PROCESSOR:STRING=bpf"
        "-DCMAKE_TRY_COMPILE_TARGET_TYPE:STRING=STATIC_LIBRARY"
        "-DCMAKE_C_COMPILER:FILEPATH=$<TARGET_FILE:bpf-capsule-cc>"
        "-DCMAKE_ASM_COMPILER:FILEPATH=$<TARGET_FILE:bpf-capsule-cc>" "-DCMAKE_AR:FILEPATH=${BPF_CAPSULE_LLVM_AR}"
        "-DCMAKE_RANLIB:FILEPATH=${BPF_CAPSULE_LLVM_RANLIB}" "-DENABLE_MALLOC:BOOL=OFF" "-D__INIT_FINI_ARRAY:BOOL=OFF"
        "-D__THREAD_LOCAL_STORAGE:BOOL=OFF" "-D__GLOBAL_ERRNO:BOOL=OFF"
        "-D__PICOLIBC_ERRNO_FUNCTION:STRING=__bpf_capsule_errno_location" "-D__SINGLE_THREAD:BOOL=ON" "-DTESTS:BOOL=OFF"
    BUILD_BYPRODUCTS "${BPF_CAPSULE_LIBC_ARCHIVE}" "${BPF_CAPSULE_LIBC_INCLUDE_DIR}/picolibc.h"
    USES_TERMINAL_CONFIGURE TRUE
    USES_TERMINAL_BUILD TRUE
    USES_TERMINAL_INSTALL TRUE
)
