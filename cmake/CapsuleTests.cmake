# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
# Test-specific wrappers around the public build API and GoogleTest.
include_guard(GLOBAL)
include(GoogleTest)

# capsule_bpf_object(<name> SOURCES ... [NODEBUG_SOURCES ...] [FLAGS ...]
#                    [RUNTIME_COMPILE_DEFINITIONS ...])
#
# Build through the same public helpers used by examples and installed
# consumers. Test links additionally enable MachineInstr verification.
# NODEBUG_SOURCES compile with -g0; the driver sources retain -g for BTF.
function(capsule_bpf_object name)
    cmake_parse_arguments(ARG "" ""
        "SOURCES;NODEBUG_SOURCES;FLAGS;RUNTIME_COMPILE_DEFINITIONS" ${ARGN})
    if(ARG_UNPARSED_ARGUMENTS)
        message(FATAL_ERROR
            "capsule_bpf_object(${name}) received unknown arguments: ${ARG_UNPARSED_ARGUMENTS}")
    endif()
    if(NOT ARG_SOURCES)
        message(FATAL_ERROR "capsule_bpf_object(${name}) needs SOURCES")
    endif()

    bpf_capsule_bitcode(debug_bitcode
        SOURCES ${ARG_SOURCES}
        COMPILE_OPTIONS -g ${ARG_FLAGS})
    set(bitcode ${debug_bitcode})
    if(ARG_NODEBUG_SOURCES)
        bpf_capsule_bitcode(nodebug_bitcode
            SOURCES ${ARG_NODEBUG_SOURCES}
            COMPILE_OPTIONS -g0 ${ARG_FLAGS})
        list(APPEND bitcode ${nodebug_bitcode})
    endif()

    set(object "${CMAKE_CURRENT_BINARY_DIR}/${name}_bpf.o")
    bpf_capsule_object(${name}_bpf_object
        OUTPUT "${object}"
        BITCODE ${bitcode}
        RUNTIME_COMPILE_DEFINITIONS ${ARG_RUNTIME_COMPILE_DEFINITIONS}
        # Production avoids LLVM's quadratic whole-CFG verifier cost. Tests
        # deliberately retain it as an end-to-end machine-pipeline contract.
        LINK_OPTIONS -verify-machineinstrs)
    bpf_capsule_skeleton(${name}_skeleton
        OUTPUT "${CMAKE_CURRENT_BINARY_DIR}/${name}.skel.h"
        OBJECT "${object}"
        NAME ${name}
        DEPENDS ${name}_bpf_object)
    if(BPF_CAPSULE_INSTALL_TEST_ARTIFACTS)
        install(FILES "${object}"
                DESTINATION "${CMAKE_INSTALL_LIBEXECDIR}/bpf-capsule/tests")
    endif()
endfunction()

# capsule_gtest_host(<name> SOURCES ... [DEPENDS ...] [INCLUDE_DIRECTORIES ...]
#                    [LIBRARIES ...])
#
# One gtest binary per suite, loading its skeleton-embedded object in-process
# through libbpf; no test spawns a subprocess. Every TEST() becomes its own
# ctest entry (PRE_TEST discovery keeps the listing run out of the build).
function(capsule_gtest_host name)
    cmake_parse_arguments(ARG "UNPRIVILEGED" "" "SOURCES;INCLUDE_DIRECTORIES;DEPENDS;LIBRARIES" ${ARGN})
    add_executable(${name} ${ARG_SOURCES})
    target_include_directories(
        ${name} PRIVATE "${CMAKE_CURRENT_BINARY_DIR}" "${CMAKE_SOURCE_DIR}/src/runtime/guest"
                        "${CMAKE_SOURCE_DIR}/src/runtime/host" "${CMAKE_SOURCE_DIR}/src/runtime/internal"
                        "${CMAKE_SOURCE_DIR}/tests/support" ${ARG_INCLUDE_DIRECTORIES}
    )
    target_link_libraries(${name} PRIVATE GTest::gtest_main ${BPF_CAPSULE_HOST_TARGET} ${ARG_LIBRARIES})
    if(ARG_DEPENDS)
        add_dependencies(${name} ${ARG_DEPENDS})
    endif()
    if(ARG_UNPRIVILEGED)
        set(test_label unprivileged)
    else()
        set(test_label privileged)
    endif()
    gtest_discover_tests(${name} DISCOVERY_MODE PRE_TEST PROPERTIES LABELS ${test_label})
    if(BPF_CAPSULE_INSTALL_TEST_ARTIFACTS)
        install(TARGETS ${name}
                RUNTIME DESTINATION "${CMAKE_INSTALL_LIBEXECDIR}/bpf-capsule/tests")
    endif()
endfunction()
