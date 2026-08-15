# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
# Cargo owns the complete no_std crate graph. The C translation unit supplies
# only the BPF program entry/control ABI; both become ordinary whole-program
# bitcode inputs to the Capsule pipeline.
bpf_capsule_bitcode(
    RUST_DRIVER_BC
    SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/rust_bpf.c
    COMPILE_OPTIONS -g
)
bpf_capsule_rust_bitcode(
    RUST_LIBRARY_BC
    MANIFEST_PATH ${CMAKE_CURRENT_SOURCE_DIR}/Cargo.toml
    PACKAGE bpf-capsule-rust-example
    LOCKED
)

bpf_capsule_object(
    rust_bpf_output
    OUTPUT rust_bpf.o
    BITCODE ${RUST_DRIVER_BC} ${RUST_LIBRARY_BC}
)

bpf_capsule_skeleton(
    rust_skeleton
    OUTPUT "${CMAKE_CURRENT_BINARY_DIR}/rust.skel.h"
    OBJECT "${CMAKE_CURRENT_BINARY_DIR}/rust_bpf.o"
    NAME rust
    DEPENDS rust_bpf_output
)

# Build the identical Cargo crate natively for the differential host check.
set(RUST_NATIVE_TARGET_DIR "${CMAKE_CURRENT_BINARY_DIR}/cargo-native")
set(RUST_NATIVE_ARCHIVE "${RUST_NATIVE_TARGET_DIR}/release/libbpf_capsule_rust_example.a")
add_custom_command(
    OUTPUT librust_native.a
    COMMAND
        "${BPF_CAPSULE_CARGO}" build --manifest-path "${CMAKE_CURRENT_SOURCE_DIR}/Cargo.toml"
        --package bpf-capsule-rust-example --target-dir "${RUST_NATIVE_TARGET_DIR}" --release
        --locked
    COMMAND "${CMAKE_COMMAND}" -E copy_if_different "${RUST_NATIVE_ARCHIVE}"
            "${CMAKE_CURRENT_BINARY_DIR}/librust_native.a"
    DEPENDS Cargo.toml Cargo.lock src/lib.rs ${BPF_CAPSULE_RUST_RUNTIME_DIR}/Cargo.toml
            ${BPF_CAPSULE_RUST_RUNTIME_DIR}/src/lib.rs
    COMMENT "Cargo native reference: bpf-capsule-rust-example"
    VERBATIM
)
add_custom_target(rust_native_library DEPENDS librust_native.a)

add_executable(rust rust_host.c "${CMAKE_CURRENT_BINARY_DIR}/rust.skel.h")
target_include_directories(rust PRIVATE "${CMAKE_CURRENT_BINARY_DIR}" ${BPF_CAPSULE_INCLUDE_DIRS})
target_compile_options(rust PRIVATE -Wall -Wextra)
target_link_libraries(rust PkgConfig::LibBpf "${CMAKE_CURRENT_BINARY_DIR}/librust_native.a")
add_dependencies(rust rust_native_library rust_skeleton)

install(TARGETS rust RUNTIME DESTINATION libexec/bpf-capsule/examples/rust)
if(BPF_CAPSULE_INSTALL_TEST_ARTIFACTS)
    install(FILES "${CMAKE_CURRENT_BINARY_DIR}/rust_bpf.o"
            DESTINATION libexec/bpf-capsule/examples/rust
    )
endif()
