# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
configure_file("${BPF_CAPSULE_CSMITH_CASE}"
    "${CMAKE_CURRENT_BINARY_DIR}/csmith_case.c" COPYONLY)

# Csmith deliberately emits old and alias-heavy C. Keep its compatibility
# flags local to this optional generated-code test.
set(CSMITH_LAX_FLAGS -w -Wno-error=incompatible-pointer-types
    -Wno-error=int-conversion)
capsule_bpf_object(csmith
    SOURCES csmith_bpf.c
    FLAGS -I${CMAKE_CURRENT_SOURCE_DIR} -I${CMAKE_CURRENT_BINARY_DIR}
          -I${BPF_CAPSULE_CSMITH_INCLUDE_DIR} ${CSMITH_LAX_FLAGS}
)
capsule_gtest_host(csmith_test
    SOURCES csmith_test.cc csmith_native.c
    DEPENDS csmith_skeleton
    INCLUDE_DIRECTORIES ${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_BINARY_DIR}
                        ${BPF_CAPSULE_CSMITH_INCLUDE_DIR}
)
target_compile_options(csmith_test PRIVATE ${CSMITH_LAX_FLAGS})

if(BPF_CAPSULE_INSTALL_TEST_ARTIFACTS)
    install(FILES CSMITH-LICENSE
        DESTINATION "${CMAKE_INSTALL_DATADIR}/licenses/bpf-capsule")
endif()
