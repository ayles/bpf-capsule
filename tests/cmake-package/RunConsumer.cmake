# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
# Prove the installed package the test suite itself was built against. The
# consumer compiles C and C++ through the exported cc/ld targets; a second
# configure pins the public helper's fail-closed argument parsing.

function(run_checked description)
    execute_process(COMMAND ${ARGN} RESULT_VARIABLE result OUTPUT_VARIABLE output ERROR_VARIABLE error)
    if(NOT result EQUAL 0)
        message(FATAL_ERROR "${description} failed (${result}):\n${output}${error}")
    endif()
    set(last_output "${output}${error}" PARENT_SCOPE)
endfunction()

file(REMOVE_RECURSE "${WORK}")
file(MAKE_DIRECTORY "${WORK}")
file(COPY "${CONSUMER_SOURCE}/" DESTINATION "${WORK}/source")

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
    "${CMAKE_COMMAND}" -S "${WORK}/source" -B "${WORK}/consumer" ${configure_toolchain}
    "-DCMAKE_BUILD_TYPE=Release"
    "-DBpfCapsule_DIR=${PACKAGE_DIR}"
    "-DBPF_CAPSULE_LINK_OPTIONS=${link_options}"
)
run_checked("building a standalone bitcode library"
    "${CMAKE_COMMAND}" --build "${WORK}/consumer" --target smoke_library --parallel 2
)
string(REGEX MATCHALL "capsule-cc: smoke_cpp" library_compiles "${last_output}")
list(LENGTH library_compiles library_compile_count)
if(NOT library_compile_count EQUAL 1)
    message(FATAL_ERROR "shared C++ library was not compiled exactly once:\n${last_output}")
endif()
if(EXISTS "${WORK}/consumer/smoke.bpf.o" OR EXISTS "${WORK}/consumer/second/second.bpf.o")
    message(FATAL_ERROR "building a bitcode archive unexpectedly linked its consumers")
endif()
run_checked("building installed-package consumers" "${CMAKE_COMMAND}" --build "${WORK}/consumer" --parallel 2)
if(last_output MATCHES "capsule-cc: smoke_cpp|capsule archive:")
    message(FATAL_ERROR "consumers rebuilt the shared library:\n${last_output}")
endif()

set(archive "${WORK}/consumer/library/libsmoke_library.a")
set(seed_archive "${WORK}/consumer/library/libsmoke_seed.a")
run_checked("listing bitcode archive members" "${LLVM_AR}" t "${archive}")
if(NOT last_output MATCHES "unused-[0-9a-f]+.bc")
    message(FATAL_ERROR "archive did not contain the unused source member:\n${last_output}")
endif()

run_checked("checking an incremental no-op build" "${CMAKE_COMMAND}" --build "${WORK}/consumer" --parallel 2)
if(last_output MATCHES "capsule-cc:|capsule-ld:|capsule archive:")
    message(FATAL_ERROR "unchanged consumer rebuilt Capsule inputs:\n${last_output}")
endif()

set(products "${seed_archive}" "${WORK}/consumer/smoke.bpf.o" "${WORK}/consumer/second/second.bpf.o")
foreach(product IN LISTS products)
    file(SHA256 "${product}" "before_${product}")
endforeach()
set(header "${WORK}/source/library/include/smoke_library.h")
file(READ "${header}" contents)
string(REPLACE "#define SMOKE_SEED 23" "#define SMOKE_SEED 24" contents "${contents}")
file(WRITE "${header}" "${contents}")
run_checked("rebuilding both consumers after a library header change"
    "${CMAKE_COMMAND}" --build "${WORK}/consumer" --parallel 2
)
foreach(product IN LISTS products)
    file(SHA256 "${product}" after)
    if(after STREQUAL "${before_${product}}")
        message(FATAL_ERROR "library header change did not update ${product}")
    endif()
endforeach()

run_checked("removing a source from the bitcode library"
    "${CMAKE_COMMAND}" -S "${WORK}/source" -B "${WORK}/consumer" -DSMOKE_REMOVE_MEMBER=ON
)
run_checked("rebuilding the shortened archive" "${CMAKE_COMMAND}" --build "${WORK}/consumer" --parallel 2)
run_checked("checking removed archive members" "${LLVM_AR}" t "${archive}")
if(last_output MATCHES "unused-")
    message(FATAL_ERROR "removed source remained in the bitcode archive:\n${last_output}")
endif()

# The installed compiler is useful without CMake too. It must find the
# packaged guest sysroot relative to itself, never a C library from the host.
get_filename_component(prefix "${PACKAGE_DIR}/../../.." ABSOLUTE)
file(MAKE_DIRECTORY "${WORK}/bin")
run_checked(
    "creating installed-compiler symlink"
    "${CMAKE_COMMAND}" -E create_symlink "${prefix}/bin/bpf-capsule-cc" "${WORK}/bin/bpf-capsule-cc"
)
run_checked(
    "compiling through the installed guest sysroot"
    "${WORK}/bin/bpf-capsule-cc" -c "${CONSUMER_SOURCE}/sysroot.c" -o "${WORK}/sysroot.bc"
)

set(object "${WORK}/consumer/smoke.bpf.o")
foreach(product IN ITEMS "${object}" "${WORK}/consumer/host_smoke")
    if(NOT EXISTS "${product}")
        message(FATAL_ERROR "installed-package consumer did not produce ${product}")
    endif()
endforeach()
run_checked("reading installed-package object" "${LLVM_READELF}" -h -S "${object}")

foreach(invalid_call IN ITEMS object library missing-library wrong-llvm)
    execute_process(
        COMMAND
            "${CMAKE_COMMAND}" -S "${CONSUMER_SOURCE}/invalid" -B "${WORK}/invalid-${invalid_call}"
            ${configure_toolchain} "-DBpfCapsule_DIR=${PACKAGE_DIR}" "-DINVALID_CALL=${invalid_call}"
        RESULT_VARIABLE invalid_result
        OUTPUT_VARIABLE invalid_output
        ERROR_VARIABLE invalid_error
    )
    if(invalid_result EQUAL 0)
        message(FATAL_ERROR "invalid ${invalid_call} invocation unexpectedly configured")
    endif()
    set(invalid_log "${invalid_output}${invalid_error}")
    if(invalid_call STREQUAL "wrong-llvm")
        set(expected "BPF_CAPSULE_LLVM_AR must be LLVM")
    elseif(invalid_call STREQUAL "missing-library")
        set(expected "Capsule library target does not exist: missing")
    else()
        set(expected "unknown arguments: TYPO")
    endif()
    if(NOT invalid_log MATCHES "${expected}")
        message(FATAL_ERROR "invalid ${invalid_call} failed for the wrong reason:\n${invalid_log}")
    endif()
endforeach()
