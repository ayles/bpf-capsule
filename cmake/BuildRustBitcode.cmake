# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
cmake_minimum_required(VERSION 3.24)

foreach(
    variable
    IN
    ITEMS
        BPF_CAPSULE_CARGO
        BPF_CAPSULE_LLVM_AR
        BPF_CAPSULE_LLVM_LINK
        BPF_CAPSULE_RUST_RUNTIME_DIR
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

# Cargo's encoded form is the only unambiguous way to pass rustc flags which
# themselves contain spaces or separators.
string(ASCII 31 rustflag_separator)
set(rustflags -Cpanic=abort -Copt-level=2 -Ccodegen-units=1 -Cdebuginfo=0)
if(BPF_CAPSULE_RUSTFLAGS)
    string(REPLACE "|" ";" extra_rustflags "${BPF_CAPSULE_RUSTFLAGS}")
    list(APPEND rustflags ${extra_rustflags})
endif()
list(JOIN rustflags "${rustflag_separator}" encoded_rustflags)

# The runtime crate is a normal dependency of the manifest; point Cargo at
# the copy shipped with this SDK (a config-based patch, no registry needed).
set(cargo_arguments
    --config
    "patch.crates-io.bpf-capsule-rt.path=\"${BPF_CAPSULE_RUST_RUNTIME_DIR}\""
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
    COMMAND
        "${CMAKE_COMMAND}" -E env "CARGO_ENCODED_RUSTFLAGS=${encoded_rustflags}" "${BPF_CAPSULE_CARGO}"
        ${cargo_arguments}
    RESULT_VARIABLE cargo_result
    OUTPUT_VARIABLE cargo_messages
    ERROR_VARIABLE cargo_diagnostics
    COMMAND_ECHO STDOUT
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
    string(JSON reason ERROR_VARIABLE json_error GET "${message}" reason)
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
            string(JSON kind GET "${message}" target kind ${index})
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

get_filename_component(output_directory "${BPF_CAPSULE_RUST_OUTPUT}" DIRECTORY)
set(extract_directory "${work_directory}/archive")
file(MAKE_DIRECTORY "${output_directory}")
file(REMOVE_RECURSE "${work_directory}")
file(MAKE_DIRECTORY "${extract_directory}")

execute_process(
    COMMAND "${BPF_CAPSULE_LLVM_AR}" x "${archive}"
    WORKING_DIRECTORY "${extract_directory}"
    RESULT_VARIABLE archive_result
    ERROR_VARIABLE archive_error
)
if(NOT archive_result EQUAL 0)
    message(FATAL_ERROR "cannot extract ${archive}: ${archive_error}")
endif()

# Cargo's staticlib also contains native metadata and object members. Keep
# only LLVM bitcode, then separate the requested crate from its dependencies.
string(REPLACE "-" "_" crate_prefix "${crate_name}")
file(GLOB archive_objects "${extract_directory}/*.o")
set(root_objects)
set(dependency_objects)
foreach(object IN LISTS archive_objects)
    file(READ "${object}" magic OFFSET 0 LIMIT 4 HEX)
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
    message(FATAL_ERROR "cannot identify ${crate_name} codegen units in ${archive}")
endif()

set(current "${work_directory}/rust-stage-0.bc")
execute_process(
    COMMAND "${BPF_CAPSULE_LLVM_LINK}" ${root_objects} -o "${current}"
    RESULT_VARIABLE link_result
    ERROR_VARIABLE link_error
)
if(NOT link_result EQUAL 0)
    message(FATAL_ERROR "cannot link root Rust crate: ${link_error}")
endif()

# --only-needed is left-to-right, so repeat until dependencies reach a fixed
# point. Eight passes is ample for the core/alloc dependency cycle and makes a
# malformed archive fail finitely.
if(dependency_objects)
    set(converged FALSE)
    foreach(pass RANGE 1 8)
        set(next "${work_directory}/rust-stage-${pass}.bc")
        execute_process(
            COMMAND "${BPF_CAPSULE_LLVM_LINK}" --only-needed "${current}" ${dependency_objects} -o "${next}"
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
