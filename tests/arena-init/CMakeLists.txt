# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
bpf_capsule_bitcode(
    ARENA_INIT_BC
    COMPILE_DEFINITIONS BPF_CAPSULE_MAX_FIBERS=8
    COMPILE_OPTIONS -g
    SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/arena_init_bpf.c
)
bpf_capsule_object(
    arena_init_bpf_output
    OUTPUT arena_init_bpf.o
    BITCODE ${ARENA_INIT_BC}
    RUNTIME_COMPILE_DEFINITIONS BPF_CAPSULE_MAX_FIBERS=8
)

add_executable(arena_init_host arena_init_host.c)
target_include_directories(arena_init_host PRIVATE ${BPF_CAPSULE_INCLUDE_DIRS})
target_link_libraries(arena_init_host PkgConfig::LibBpf pthread)
add_dependencies(arena_init_host arena_init_bpf_output)

install(TARGETS arena_init_host RUNTIME DESTINATION libexec/bpf-capsule/tests/arena-init)
install(FILES "${CMAKE_CURRENT_BINARY_DIR}/arena_init_bpf.o"
        DESTINATION libexec/bpf-capsule/tests/arena-init
)
