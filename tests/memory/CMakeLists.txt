# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
bpf_capsule_bitcode(
    MEMORY_TEST_BC
    COMPILE_OPTIONS -g
    SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/memory_bpf.c
)
bpf_capsule_object(
    memory_test_bpf_output
    OUTPUT memory_test_bpf.o
    BITCODE ${MEMORY_TEST_BC}
)

if(NOT BPF_CAPSULE_HAS_ARENA)
    add_custom_target(
        memory_width_contract ALL
        COMMAND
            "${CMAKE_COMMAND}" "-DLLVM_OBJDUMP=${BPF_CAPSULE_LLVM_OBJDUMP}"
            "-DOBJECT=${CMAKE_CURRENT_BINARY_DIR}/memory_test_bpf.o" -P
            "${CMAKE_CURRENT_SOURCE_DIR}/verify-width.cmake"
        DEPENDS memory_test_bpf_output
        COMMENT "BPF fixed-memory word-access contract"
        VERBATIM
    )
endif()

add_executable(memory_test_host memory_host.c)
target_include_directories(
    memory_test_host PRIVATE ${BPF_CAPSULE_INCLUDE_DIRS} "${CMAKE_CURRENT_SOURCE_DIR}"
)
target_link_libraries(memory_test_host PkgConfig::LibBpf)
add_dependencies(memory_test_host memory_test_bpf_output)

install(TARGETS memory_test_host RUNTIME DESTINATION libexec/bpf-capsule/tests/memory)
install(FILES "${CMAKE_CURRENT_BINARY_DIR}/memory_test_bpf.o"
        DESTINATION libexec/bpf-capsule/tests/memory
)
