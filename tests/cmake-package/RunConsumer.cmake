# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
# Prove the installed package the test suite itself was built against. The
# consumer compiles C and C++ through the exported cc/ld targets; a second
# configure pins the public helper's fail-closed argument parsing.

function(run_checked description)
    execute_process(COMMAND ${ARGN} RESULT_VARIABLE result OUTPUT_VARIABLE output ERROR_VARIABLE error)
    if(NOT result EQUAL 0)
        message(FATAL_ERROR "${description} failed (${result}):\n${output}${error}")
    endif()
endfunction()

file(REMOVE_RECURSE "${WORK}")
file(MAKE_DIRECTORY "${WORK}")

# A nested project is still part of this configured build. Reuse its generator
# and compilers so the contract neither guesses at Make versus Ninja nor finds
# a different host toolchain from the ambient PATH.
set(configure_toolchain)
if(DEFINED PROJECT_GENERATOR AND NOT PROJECT_GENERATOR STREQUAL "")
    list(APPEND configure_toolchain -G "${PROJECT_GENERATOR}")
endif()
if(DEFINED PROJECT_GENERATOR_PLATFORM AND NOT PROJECT_GENERATOR_PLATFORM STREQUAL "")
    list(APPEND configure_toolchain -A "${PROJECT_GENERATOR_PLATFORM}")
endif()
if(DEFINED PROJECT_GENERATOR_TOOLSET AND NOT PROJECT_GENERATOR_TOOLSET STREQUAL "")
    list(APPEND configure_toolchain -T "${PROJECT_GENERATOR_TOOLSET}")
endif()
if(DEFINED PROJECT_MAKE_PROGRAM AND NOT PROJECT_MAKE_PROGRAM STREQUAL "")
    list(APPEND configure_toolchain "-DCMAKE_MAKE_PROGRAM=${PROJECT_MAKE_PROGRAM}")
endif()
if(DEFINED PROJECT_C_COMPILER AND NOT PROJECT_C_COMPILER STREQUAL "")
    list(APPEND configure_toolchain "-DCMAKE_C_COMPILER=${PROJECT_C_COMPILER}")
endif()
if(DEFINED PROJECT_CXX_COMPILER AND NOT PROJECT_CXX_COMPILER STREQUAL "")
    list(APPEND configure_toolchain "-DCMAKE_CXX_COMPILER=${PROJECT_CXX_COMPILER}")
endif()

# A CMake cache value is one argv element even when the value itself is a
# semicolon-separated list. Preserve that list through run_checked's ARGN.
string(REPLACE ";" "\\;" link_options "${LINK_OPTIONS}")

run_checked("configuring installed-package consumer"
    "${CMAKE_COMMAND}" -S "${CONSUMER_SOURCE}" -B "${WORK}/consumer" ${configure_toolchain}
    "-DCMAKE_BUILD_TYPE=Release"
    "-DBpfCapsule_DIR=${PACKAGE_DIR}"
    "-DBPF_CAPSULE_LINK_OPTIONS=${link_options}"
)
run_checked("building installed-package consumer"
    "${CMAKE_COMMAND}" --build "${WORK}/consumer" --parallel 2
)

set(object "${WORK}/consumer/smoke.bpf.o")
foreach(product IN ITEMS "${object}" "${WORK}/consumer/host_smoke")
    if(NOT EXISTS "${product}")
        message(FATAL_ERROR "installed-package consumer did not produce ${product}")
    endif()
endforeach()
run_checked("reading installed-package object" "${LLVM_READELF}" -h -S "${object}")

execute_process(
    COMMAND
        "${CMAKE_COMMAND}" -S "${CONSUMER_SOURCE}/invalid" -B "${WORK}/invalid" ${configure_toolchain}
        "-DBpfCapsule_DIR=${PACKAGE_DIR}"
    RESULT_VARIABLE invalid_result
    OUTPUT_VARIABLE invalid_output
    ERROR_VARIABLE invalid_error
)
if(invalid_result EQUAL 0)
    message(FATAL_ERROR "invalid installed-package helper invocation unexpectedly configured")
endif()
set(invalid_log "${invalid_output}${invalid_error}")
if(NOT invalid_log MATCHES "unknown arguments: TYPO")
    message(FATAL_ERROR "invalid consumer failed for the wrong reason:\n${invalid_log}")
endif()
