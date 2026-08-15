# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
cmake_minimum_required(VERSION 3.21)

foreach(
    variable IN
    ITEMS BPF_CAPSULE_CARGO
          BPF_CAPSULE_LLVM_AR
          BPF_CAPSULE_LLVM_LINK
          BPF_CAPSULE_CARGO_MANIFEST
          BPF_CAPSULE_CARGO_PACKAGE
          BPF_CAPSULE_CARGO_TARGET_DIR
          BPF_CAPSULE_RUST_OUTPUT
)
    if(NOT DEFINED ${variable} OR "${${variable}}" STREQUAL "")
        message(FATAL_ERROR "BuildRustBitcode.cmake needs ${variable}")
    endif()
endforeach()

set(work_directory "${BPF_CAPSULE_CARGO_TARGET_DIR}/bpf-capsule-link")
file(REMOVE_RECURSE "${work_directory}")
file(MAKE_DIRECTORY "${work_directory}")

string(ASCII 31 rustflag_separator)
set(rustflags -Cpanic=abort -Copt-level=2 -Ccodegen-units=1 -Cdebuginfo=0)
if(BPF_CAPSULE_RUSTFLAGS)
    string(REPLACE "|" ";" extra_rustflags "${BPF_CAPSULE_RUSTFLAGS}")
    list(APPEND rustflags ${extra_rustflags})
endif()
list(JOIN rustflags "${rustflag_separator}" encoded_rustflags)

set(cargo_arguments
    rustc
    --manifest-path
    "${BPF_CAPSULE_CARGO_MANIFEST}"
    --package
    "${BPF_CAPSULE_CARGO_PACKAGE}"
    --target
    bpfel-unknown-none
    --target-dir
    "${BPF_CAPSULE_CARGO_TARGET_DIR}"
    --release
    --lib
    --message-format=json-render-diagnostics
)
if(BPF_CAPSULE_CARGO_FEATURES)
    list(APPEND cargo_arguments --features "${BPF_CAPSULE_CARGO_FEATURES}")
endif()
if(BPF_CAPSULE_CARGO_LOCKED)
    list(APPEND cargo_arguments --locked)
endif()
if(BPF_CAPSULE_CARGO_NO_DEFAULT_FEATURES)
    list(APPEND cargo_arguments --no-default-features)
endif()
list(APPEND cargo_arguments -- --crate-type staticlib)

execute_process(
    COMMAND "${CMAKE_COMMAND}" -E env "CARGO_ENCODED_RUSTFLAGS=${encoded_rustflags}"
            "${BPF_CAPSULE_CARGO}" ${cargo_arguments}
    RESULT_VARIABLE cargo_result
    OUTPUT_VARIABLE cargo_messages
    ERROR_VARIABLE cargo_diagnostics COMMAND_ECHO STDOUT
)
if(NOT cargo_result EQUAL 0)
    message(FATAL_ERROR "Cargo failed for ${BPF_CAPSULE_CARGO_PACKAGE}:\n${cargo_diagnostics}")
endif()
if(cargo_diagnostics)
    message(STATUS "${cargo_diagnostics}")
endif()

set(messages_file "${work_directory}/cargo-messages.jsonl")
file(WRITE "${messages_file}" "${cargo_messages}")
file(STRINGS "${messages_file}" messages)
set(archive)
set(crate_name)
foreach(message IN LISTS messages)
    string(
        JSON
        reason
        ERROR_VARIABLE
        json_error
        GET
        "${message}"
        reason
    )
    if(json_error OR NOT reason STREQUAL "compiler-artifact")
        continue()
    endif()
    string(JSON kind_count ERROR_VARIABLE json_error LENGTH "${message}" target kind)
    if(json_error)
        continue()
    endif()
    set(is_staticlib FALSE)
    if(kind_count GREATER 0)
        math(EXPR kind_last "${kind_count} - 1")
        foreach(index RANGE 0 ${kind_last})
            string(
                JSON
                kind
                GET
                "${message}"
                target
                kind
                ${index}
            )
            if(kind STREQUAL "staticlib")
                set(is_staticlib TRUE)
            endif()
        endforeach()
    endif()
    if(NOT is_staticlib)
        continue()
    endif()
    string(JSON candidate_crate_name GET "${message}" target name)
    string(JSON filename_count LENGTH "${message}" filenames)
    if(filename_count GREATER 0)
        math(EXPR filename_last "${filename_count} - 1")
        foreach(index RANGE 0 ${filename_last})
            string(JSON filename GET "${message}" filenames ${index})
            if(filename MATCHES "\\.(a|lib)$")
                set(archive "${filename}")
                set(crate_name "${candidate_crate_name}")
            endif()
        endforeach()
    endif()
endforeach()
if(NOT archive OR NOT EXISTS "${archive}")
    message(FATAL_ERROR "Cargo produced no staticlib for ${BPF_CAPSULE_CARGO_PACKAGE}")
endif()

set(BPF_CAPSULE_RUST_ARCHIVE "${archive}")
set(BPF_CAPSULE_RUST_CRATE_NAME "${crate_name}")
set(BPF_CAPSULE_RUST_WORK_DIRECTORY "${work_directory}")
include("${CMAKE_CURRENT_LIST_DIR}/ExtractRustBitcode.cmake")
