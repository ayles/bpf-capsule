# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
# The two toolchain binaries. bpf-capsule-ld links the pass library and LLVM
# into one self-contained linker; bpf-capsule-cc is an exec wrapper around
# clang. Everything downstream (tests, benchmarks, embedders) only ever
# invokes these two tools.

configure_file(tool_config.h.in "${CMAKE_CURRENT_BINARY_DIR}/tool_config.h")

add_executable(bpf-capsule-ld bpf-capsule-ld/main.cpp)
target_link_libraries(bpf-capsule-ld PRIVATE bpf_capsule_passes LLVM)
target_compile_options(bpf-capsule-ld PRIVATE -fno-rtti)
set_target_properties(bpf-capsule-ld PROPERTIES EXPORT_NAME ld)

add_executable(bpf-capsule-cc bpf-capsule-cc/main.cpp)
target_include_directories(bpf-capsule-cc PRIVATE "${CMAKE_CURRENT_BINARY_DIR}")
set_target_properties(bpf-capsule-cc PROPERTIES EXPORT_NAME cc)

install(TARGETS bpf-capsule-cc bpf-capsule-ld EXPORT BpfCapsuleTargets
        RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}")
