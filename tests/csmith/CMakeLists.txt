# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
configure_file("${BPF_CAPSULE_CSMITH_CASE}" "${CMAKE_CURRENT_BINARY_DIR}/csmith_case.c" COPYONLY)

# -w silences warnings, but clang >= 17 treats csmith's char*-aliased float
# hashing as an error by default; downgrade it for generated cases only.
set(CSMITH_LAX_FLAGS -w -Wno-error=incompatible-pointer-types -Wno-error=int-conversion)
bpf_capsule_bitcode(
    CSMITH_TEST_BC
    SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/csmith_bpf.c
    INCLUDE_DIRECTORIES ${BPF_CAPSULE_CSMITH_INCLUDE_DIR} ${CMAKE_CURRENT_BINARY_DIR}
    COMPILE_OPTIONS ${CSMITH_LAX_FLAGS} -g
    DEPENDS "${CMAKE_CURRENT_BINARY_DIR}/csmith_case.c"
)
bpf_capsule_object(
    csmith_test_bpf_output
    OUTPUT csmith_test_bpf.o
    BITCODE ${CSMITH_TEST_BC}
)
bpf_capsule_skeleton(
    csmith_test_skeleton
    OUTPUT "${CMAKE_CURRENT_BINARY_DIR}/csmith.skel.h"
    OBJECT "${CMAKE_CURRENT_BINARY_DIR}/csmith_test_bpf.o"
    NAME csmith_test
    DEPENDS csmith_test_bpf_output
)

add_executable(csmith_test_host csmith_host.c "${CMAKE_CURRENT_BINARY_DIR}/csmith.skel.h")
target_include_directories(
    csmith_test_host PRIVATE ${BPF_CAPSULE_INCLUDE_DIRS} "${BPF_CAPSULE_CSMITH_INCLUDE_DIR}"
                             "${CMAKE_CURRENT_BINARY_DIR}"
)
target_link_libraries(csmith_test_host PkgConfig::LibBpf)
target_compile_options(csmith_test_host PRIVATE ${CSMITH_LAX_FLAGS})
add_dependencies(csmith_test_host csmith_test_skeleton)

if(BPF_CAPSULE_INSTALL_TEST_ARTIFACTS)
    install(TARGETS csmith_test_host RUNTIME DESTINATION libexec/bpf-capsule/tests/csmith)
    install(FILES "${CMAKE_CURRENT_BINARY_DIR}/csmith_test_bpf.o"
            DESTINATION libexec/bpf-capsule/tests/csmith
    )
    install(FILES CSMITH-LICENSE DESTINATION share/licenses/bpf-capsule-examples/csmith)
endif()
