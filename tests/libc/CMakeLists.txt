# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
bpf_capsule_bitcode(
    LIBC_TEST_BC
    SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/libc_bpf.c ${BPF_CAPSULE_LIBC_DIR}/freestanding.c
            ${BPF_CAPSULE_LIBC_DIR}/tlsf.c ${BPF_CAPSULE_LIBC_DIR}/softfloat.c
            ${BPF_CAPSULE_LIBC_DIR}/mathfns.c
    INCLUDE_DIRECTORIES ${BPF_CAPSULE_LIBC_DIR} ${BPF_CAPSULE_LIBC_DIR}/include
    COMPILE_DEFINITIONS BPF_CAPSULE_DRIVE_LEVEL=16
    COMPILE_OPTIONS -g
)
bpf_capsule_object(
    libc_test_bpf_output
    OUTPUT libc_test_bpf.o
    BITCODE ${LIBC_TEST_BC}
    RUNTIME_COMPILE_DEFINITIONS BPF_CAPSULE_DRIVE_LEVEL=16
)

add_executable(libc_test_host libc_host.c)
target_include_directories(
    libc_test_host PRIVATE ${BPF_CAPSULE_INCLUDE_DIRS} ${CMAKE_CURRENT_SOURCE_DIR}
)
target_link_libraries(libc_test_host PkgConfig::LibBpf)
add_dependencies(libc_test_host libc_test_bpf_output)

install(TARGETS libc_test_host RUNTIME DESTINATION libexec/bpf-capsule/tests/libc)
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/libc_test_bpf.o
        DESTINATION libexec/bpf-capsule/tests/libc
)
