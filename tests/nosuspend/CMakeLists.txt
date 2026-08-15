# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
bpf_capsule_bitcode(
    NOSUSPEND_TEST_BC
    COMPILE_OPTIONS -g
    SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/nosuspend_bpf.c
)
bpf_capsule_object(
    nosuspend_test_bpf_output
    OUTPUT nosuspend_test_bpf.o
    BITCODE ${NOSUSPEND_TEST_BC}
)

add_executable(nosuspend_test_host nosuspend_host.c)
target_include_directories(nosuspend_test_host PRIVATE ${BPF_CAPSULE_INCLUDE_DIRS})
target_link_libraries(nosuspend_test_host PkgConfig::LibBpf)
add_dependencies(nosuspend_test_host nosuspend_test_bpf_output)

install(TARGETS nosuspend_test_host RUNTIME DESTINATION libexec/bpf-capsule/tests/nosuspend)
install(FILES "${CMAKE_CURRENT_BINARY_DIR}/nosuspend_test_bpf.o"
        DESTINATION libexec/bpf-capsule/tests/nosuspend
)
