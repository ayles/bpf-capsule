# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
bpf_capsule_bitcode(
    VERIFIER_POINTER_TEST_BC
    COMPILE_OPTIONS -g
    SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/verifier_pointer_bpf.c
)
bpf_capsule_object(
    verifier_pointer_test_bpf_output
    OUTPUT verifier_pointer_test_bpf.o
    BITCODE ${VERIFIER_POINTER_TEST_BC}
)

add_executable(verifier_pointer_test_host verifier_pointer_host.c)
target_include_directories(
    verifier_pointer_test_host PRIVATE ${BPF_CAPSULE_INCLUDE_DIRS} "${CMAKE_CURRENT_SOURCE_DIR}"
)
target_link_libraries(verifier_pointer_test_host PkgConfig::LibBpf)
add_dependencies(verifier_pointer_test_host verifier_pointer_test_bpf_output)

add_custom_target(
    verifier_pointer_lifetime_contract ALL
    COMMAND
        "${CMAKE_COMMAND}" "-DOPT=${BPF_CAPSULE_OPT}" "-DPLUGIN=$<TARGET_FILE:bpf_capsule_pass>"
        "-DSOURCE_DIR=${CMAKE_CURRENT_SOURCE_DIR}" -P
        "${CMAKE_CURRENT_SOURCE_DIR}/verify-negative.cmake"
    DEPENDS bpf_capsule_pass
    COMMENT "Verifier-pointer suspension lifetime contract"
    VERBATIM
)

install(TARGETS verifier_pointer_test_host
        RUNTIME DESTINATION libexec/bpf-capsule/tests/verifier-pointer
)
install(FILES "${CMAKE_CURRENT_BINARY_DIR}/verifier_pointer_test_bpf.o"
        DESTINATION libexec/bpf-capsule/tests/verifier-pointer
)
