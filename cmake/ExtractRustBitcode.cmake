# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
cmake_minimum_required(VERSION 3.21)

foreach(variable IN
        ITEMS BPF_CAPSULE_LLVM_AR BPF_CAPSULE_LLVM_LINK BPF_CAPSULE_RUST_ARCHIVE
              BPF_CAPSULE_RUST_CRATE_NAME BPF_CAPSULE_RUST_WORK_DIRECTORY BPF_CAPSULE_RUST_OUTPUT
)
    if(NOT DEFINED ${variable} OR "${${variable}}" STREQUAL "")
        message(FATAL_ERROR "ExtractRustBitcode.cmake needs ${variable}")
    endif()
endforeach()

if(NOT EXISTS "${BPF_CAPSULE_RUST_ARCHIVE}")
    message(FATAL_ERROR "Rust archive does not exist: ${BPF_CAPSULE_RUST_ARCHIVE}")
endif()

get_filename_component(output_directory "${BPF_CAPSULE_RUST_OUTPUT}" DIRECTORY)
set(extract_directory "${BPF_CAPSULE_RUST_WORK_DIRECTORY}/archive")
file(MAKE_DIRECTORY "${output_directory}")
file(REMOVE_RECURSE "${BPF_CAPSULE_RUST_WORK_DIRECTORY}")
file(MAKE_DIRECTORY "${extract_directory}")

execute_process(
    COMMAND "${BPF_CAPSULE_LLVM_AR}" x "${BPF_CAPSULE_RUST_ARCHIVE}"
    WORKING_DIRECTORY "${extract_directory}"
    RESULT_VARIABLE archive_result
    ERROR_VARIABLE archive_error
)
if(NOT archive_result EQUAL 0)
    message(FATAL_ERROR "cannot extract ${BPF_CAPSULE_RUST_ARCHIVE}: ${archive_error}")
endif()

string(REPLACE "-" "_" crate_prefix "${BPF_CAPSULE_RUST_CRATE_NAME}")
file(GLOB archive_objects "${extract_directory}/*.o")
set(root_objects)
set(dependency_objects)
foreach(object IN LISTS archive_objects)
    file(
        READ "${object}" magic
        OFFSET 0
        LIMIT 4
        HEX
    )
    if(NOT magic STREQUAL "4243c0de" AND NOT magic STREQUAL "dec0170b")
        continue()
    endif()
    get_filename_component(member "${object}" NAME)
    if(member MATCHES "^${crate_prefix}.*\\.rcgu\\.o$")
        list(APPEND root_objects "${object}")
    else()
        list(APPEND dependency_objects "${object}")
    endif()
endforeach()
if(NOT root_objects)
    message(
        FATAL_ERROR
            "cannot identify ${BPF_CAPSULE_RUST_CRATE_NAME} codegen units in ${BPF_CAPSULE_RUST_ARCHIVE}"
    )
endif()

set(current "${BPF_CAPSULE_RUST_WORK_DIRECTORY}/rust-stage-0.bc")
execute_process(
    COMMAND "${BPF_CAPSULE_LLVM_LINK}" ${root_objects} -o "${current}"
    RESULT_VARIABLE link_result
    ERROR_VARIABLE link_error
)
if(NOT link_result EQUAL 0)
    message(FATAL_ERROR "cannot link root Rust crate: ${link_error}")
endif()

# --only-needed resolves symbols in one left-to-right pass. Dependencies may
# refer back to an archive member considered earlier, so repeat until the
# module stops changing. Eight passes is far beyond the core -> alloc -> core
# cycle in the Rust sysroot while still turning malformed archives into a
# finite, useful failure.
if(dependency_objects)
    set(converged FALSE)
    foreach(pass RANGE 1 8)
        set(next "${BPF_CAPSULE_RUST_WORK_DIRECTORY}/rust-stage-${pass}.bc")
        execute_process(
            COMMAND "${BPF_CAPSULE_LLVM_LINK}" --only-needed "${current}" ${dependency_objects} -o
                    "${next}"
            RESULT_VARIABLE link_result
            ERROR_VARIABLE link_error
        )
        if(NOT link_result EQUAL 0)
            message(FATAL_ERROR "cannot resolve Rust archive on pass ${pass}: ${link_error}")
        endif()
        file(SHA256 "${current}" current_hash)
        file(SHA256 "${next}" next_hash)
        set(current "${next}")
        if(current_hash STREQUAL next_hash)
            set(converged TRUE)
            break()
        endif()
    endforeach()
    if(NOT converged)
        message(FATAL_ERROR "Rust archive did not reach a fixed point after eight link passes")
    endif()
endif()

configure_file("${current}" "${BPF_CAPSULE_RUST_OUTPUT}" COPYONLY)
