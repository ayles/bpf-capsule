# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
bpf_capsule_bitcode(
    YIELD_TEST_BC
    COMPILE_DEFINITIONS BPF_CAPSULE_DRIVE_LEVEL=16
    COMPILE_OPTIONS -g
    SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/yield_bpf.c
)
bpf_capsule_object(
    yield_test_bpf_output
    OUTPUT yield_test_bpf.o
    BITCODE ${YIELD_TEST_BC}
    RUNTIME_COMPILE_DEFINITIONS BPF_CAPSULE_DRIVE_LEVEL=16
)

add_executable(yield_test_host yield_host.c)
target_include_directories(yield_test_host PRIVATE ${BPF_CAPSULE_INCLUDE_DIRS})
target_link_libraries(yield_test_host PkgConfig::LibBpf)
add_dependencies(yield_test_host yield_test_bpf_output)

add_custom_target(
    yield_contract ALL
    COMMAND
        "${CMAKE_COMMAND}" "-DOPT=${BPF_CAPSULE_OPT}" "-DPLUGIN=$<TARGET_FILE:bpf_capsule_pass>"
        "-DSOURCE=${CMAKE_CURRENT_SOURCE_DIR}/unsupported-native.ll" -P
        "${CMAKE_CURRENT_SOURCE_DIR}/verify-negative.cmake"
    DEPENDS bpf_capsule_pass
    COMMENT "Capsule yield domain contract"
    VERBATIM
)

install(TARGETS yield_test_host RUNTIME DESTINATION libexec/bpf-capsule/tests/yield)
install(FILES "${CMAKE_CURRENT_BINARY_DIR}/yield_test_bpf.o"
        DESTINATION libexec/bpf-capsule/tests/yield
)
