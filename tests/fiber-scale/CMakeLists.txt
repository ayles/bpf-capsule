# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
bpf_capsule_bitcode(
    FIBER_SCALE_BC
    COMPILE_DEFINITIONS BPF_CAPSULE_MAX_FIBERS=512 BPF_CAPSULE_DRIVE_LEVEL=16
    COMPILE_OPTIONS -g
    SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/fiber_scale_bpf.c
)
bpf_capsule_object(
    fiber_scale_bpf_output
    OUTPUT fiber_scale_bpf.o
    BITCODE ${FIBER_SCALE_BC}
    RUNTIME_COMPILE_DEFINITIONS BPF_CAPSULE_MAX_FIBERS=512 BPF_CAPSULE_DRIVE_LEVEL=16
)

add_executable(fiber_scale_host fiber_scale_host.c)
target_include_directories(fiber_scale_host PRIVATE ${BPF_CAPSULE_INCLUDE_DIRS})
target_link_libraries(fiber_scale_host PkgConfig::LibBpf)
add_dependencies(fiber_scale_host fiber_scale_bpf_output)

install(TARGETS fiber_scale_host RUNTIME DESTINATION libexec/bpf-capsule/tests/fiber-scale)
install(FILES "${CMAKE_CURRENT_BINARY_DIR}/fiber_scale_bpf.o"
        DESTINATION libexec/bpf-capsule/tests/fiber-scale
)
