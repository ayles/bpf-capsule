# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
cmake_minimum_required(VERSION 3.24)
project(BpfCapsuleRust LANGUAGES C)

include(GNUInstallDirs)

set(CMAKE_C_STANDARD 17)
set(CMAKE_C_STANDARD_REQUIRED ON)

find_package(BpfCapsule CONFIG REQUIRED)

bpf_capsule_rust_bitcode(rust_library_bitcode MANIFEST_PATH Cargo.toml PACKAGE bpf-capsule-rust-example LOCKED)

bpf_capsule_object(
    rust_bpf
    OUTPUT rust.bpf.o
    SOURCES rust_bpf.c
    BITCODE ${rust_library_bitcode}
    COMPILE_OPTIONS -g
    LINK_OPTIONS ${BPF_CAPSULE_LINK_OPTIONS}
)

bpf_capsule_skeleton(rust_skeleton OUTPUT rust.skel.h OBJECT "${rust_bpf}" NAME rust)

add_executable(rust rust_host.c)
target_compile_options(rust PRIVATE -Wall -Wextra)
target_link_libraries(rust PRIVATE BpfCapsule::host rust_skeleton)

install(TARGETS rust RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}")
install(FILES "${rust_bpf}" DESTINATION "${CMAKE_INSTALL_BINDIR}")
