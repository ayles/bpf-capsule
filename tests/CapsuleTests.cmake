# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
# Test-specific wrappers around the public build API and GoogleTest.
include_guard(GLOBAL)
include(GoogleTest)

# capsule_test_object(<name> SOURCES ... [DEPENDS ...]
#                     [INCLUDE_DIRECTORIES ...] [COMPILE_DEFINITIONS ...]
#                     [COMPILE_OPTIONS ...] [SYSTEM_COMPILE_DEFINITIONS ...]
#                     [LINK_OPTIONS ...])
#
# Build through the same public helpers used by examples and installed
# consumers. Test links additionally enable MachineInstr verification.
# The generated skeleton embeds the object, so only the host test binary needs
# to be installed for the kernel VM matrix.
function(capsule_test_object name)
    cmake_parse_arguments(
        ARG
        ""
        ""
        "SOURCES;DEPENDS;INCLUDE_DIRECTORIES;COMPILE_DEFINITIONS;COMPILE_OPTIONS;SYSTEM_COMPILE_DEFINITIONS;LINK_OPTIONS"
        ${ARGN}
    )
    if(ARG_UNPARSED_ARGUMENTS)
        message(FATAL_ERROR "capsule_test_object(${name}) received unknown arguments: ${ARG_UNPARSED_ARGUMENTS}")
    endif()
    if(NOT ARG_SOURCES)
        message(FATAL_ERROR "capsule_test_object(${name}) needs SOURCES")
    endif()

    bpf_capsule_object(
        object
        OUTPUT "${name}.bpf.o"
        SOURCES ${ARG_SOURCES}
        DEPENDS ${ARG_DEPENDS}
        INCLUDE_DIRECTORIES ${ARG_INCLUDE_DIRECTORIES}
        COMPILE_DEFINITIONS ${ARG_COMPILE_DEFINITIONS}
        COMPILE_OPTIONS -g ${ARG_COMPILE_OPTIONS}
        SYSTEM_COMPILE_DEFINITIONS ${ARG_SYSTEM_COMPILE_DEFINITIONS}
        # Production avoids LLVM's quadratic whole-CFG verifier cost. Tests
        # deliberately retain it as an end-to-end machine-pipeline contract.
        LINK_OPTIONS ${BPF_CAPSULE_LINK_OPTIONS} -verify-machineinstrs ${ARG_LINK_OPTIONS}
    )
    add_custom_target(${name}_object ALL DEPENDS "${object}")
    bpf_capsule_skeleton(${name}_skeleton OUTPUT "${name}.skel.h" OBJECT "${object}" NAME ${name})
    add_dependencies(${name}_skeleton_generate ${name}_object)
endfunction()

# capsule_gtest_host(<name> SOURCES ... [SKELETONS ...] [INCLUDE_DIRECTORIES ...]
#                    [LIBRARIES ...])
#
# One gtest binary per suite, loading its skeleton-embedded object in-process
# through libbpf; no test spawns a subprocess. Every TEST() becomes its own
# ctest entry (PRE_TEST discovery keeps the listing run out of the build).
function(capsule_gtest_host name)
    cmake_parse_arguments(ARG "UNPRIVILEGED" "" "SOURCES;INCLUDE_DIRECTORIES;SKELETONS;LIBRARIES" ${ARGN})
    if(ARG_UNPARSED_ARGUMENTS)
        message(FATAL_ERROR "capsule_gtest_host(${name}) received unknown arguments: ${ARG_UNPARSED_ARGUMENTS}")
    endif()
    if(NOT ARG_SOURCES)
        message(FATAL_ERROR "capsule_gtest_host(${name}) needs SOURCES")
    endif()
    add_executable(${name} ${ARG_SOURCES})
    target_include_directories(
        ${name}
        PRIVATE "${BPF_CAPSULE_INTERNAL_INCLUDE_DIR}" "${PROJECT_SOURCE_DIR}/support" ${ARG_INCLUDE_DIRECTORIES}
    )
    target_link_libraries(${name} PRIVATE GTest::gtest_main BpfCapsule::host ${ARG_SKELETONS} ${ARG_LIBRARIES})
    if(ARG_UNPRIVILEGED)
        set(test_label unprivileged)
    else()
        set(test_label privileged)
    endif()
    gtest_discover_tests(${name} DISCOVERY_MODE PRE_TEST PROPERTIES LABELS ${test_label})
    install(TARGETS ${name} RUNTIME DESTINATION "${CMAKE_INSTALL_LIBEXECDIR}/bpf-capsule/tests")
endfunction()
