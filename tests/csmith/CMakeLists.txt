# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
set(csmith_case "${CMAKE_CURRENT_BINARY_DIR}/csmith_case.c")
add_custom_command(
    OUTPUT "${csmith_case}"
    COMMAND
        "${CSMITH_EXECUTABLE}" --seed 29 --no-argc --no-float --int128 --uint128 --concise --max-funcs 6
        --max-block-depth 4 --max-block-size 4 --max-expr-complexity 10 --max-array-len-per-dim 12 --max-pointer-depth 3
        --max-struct-fields 12 --max-union-fields 8 --output "${csmith_case}"
    COMMENT "generate: deterministic Csmith program"
    VERBATIM
)
add_custom_target(csmith_case DEPENDS "${csmith_case}")

# Csmith deliberately emits old and alias-heavy C. Keep its compatibility
# flags local to this optional generated-code test.
set(csmith_lax_options -w -Wno-error=incompatible-pointer-types -Wno-error=int-conversion)
capsule_test_object(
    csmith
    SOURCES csmith_bpf.c
    DEPENDS csmith_case
    INCLUDE_DIRECTORIES
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${CMAKE_CURRENT_BINARY_DIR}
        ${CSMITH_INCLUDE_DIR}
        ${BPF_CAPSULE_INTERNAL_INCLUDE_DIR}
    COMPILE_OPTIONS ${csmith_lax_options}
)
capsule_gtest_host(
    csmith_test
    SOURCES csmith_test.cc csmith_native.c
    SKELETONS csmith_skeleton
    INCLUDE_DIRECTORIES ${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_BINARY_DIR} ${CSMITH_INCLUDE_DIR}
)
add_dependencies(csmith_test csmith_case)
target_compile_options(csmith_test PRIVATE ${csmith_lax_options})

install(FILES CSMITH-LICENSE DESTINATION "${CMAKE_INSTALL_DATADIR}/licenses/bpf-capsule")
