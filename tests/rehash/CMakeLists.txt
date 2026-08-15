# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
bpf_capsule_bitcode(
    REHASH_TEST_BC
    SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/rehash_bpf.c ${BPF_CAPSULE_LIBC_DIR}/freestanding.c
            ${BPF_CAPSULE_LIBC_DIR}/tlsf.c
    INCLUDE_DIRECTORIES ${BPF_CAPSULE_LIBC_DIR} ${BPF_CAPSULE_LIBC_DIR}/include
    COMPILE_OPTIONS -g
)
bpf_capsule_object(
    rehash_test_bpf_output
    OUTPUT rehash_test_bpf.o
    BITCODE ${REHASH_TEST_BC}
)

add_executable(rehash_test_host rehash_host.c)
target_include_directories(
    rehash_test_host PRIVATE ${BPF_CAPSULE_INCLUDE_DIRS} "${CMAKE_CURRENT_SOURCE_DIR}"
)
target_link_libraries(rehash_test_host PkgConfig::LibBpf)
add_dependencies(rehash_test_host rehash_test_bpf_output)

install(TARGETS rehash_test_host RUNTIME DESTINATION libexec/bpf-capsule/tests/rehash)
install(FILES "${CMAKE_CURRENT_BINARY_DIR}/rehash_test_bpf.o"
        DESTINATION libexec/bpf-capsule/tests/rehash
)
