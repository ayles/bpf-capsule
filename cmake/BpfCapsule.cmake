# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
include_guard(GLOBAL)
# All tools must come from one LLVM installation. Mixing (for example) clang
# 21 bitcode with opt 20 produces opaque and often late failures.
find_program(BPF_CAPSULE_LLC NAMES llc REQUIRED)
get_filename_component(BPF_CAPSULE_LLVM_BIN_DIR "${BPF_CAPSULE_LLC}" DIRECTORY)
execute_process(
    COMMAND "${BPF_CAPSULE_LLC}" --version
    OUTPUT_VARIABLE bpf_capsule_llc_version
    OUTPUT_STRIP_TRAILING_WHITESPACE
)
string(REGEX MATCH "LLVM version ([0-9]+)" _ "${bpf_capsule_llc_version}")
set(BPF_CAPSULE_LLVM_MAJOR "${CMAKE_MATCH_1}")
if(NOT BPF_CAPSULE_LLVM_MAJOR)
    message(FATAL_ERROR "could not determine llc version from: ${BPF_CAPSULE_LLC}")
endif()

# Clang is a separate Nix output, while opt/llvm-link sit beside llc. Prefer
# the versioned, unwrapped clang executable and reject mixed LLVM majors.
find_program(
    BPF_CAPSULE_CLANG
    NAMES clang-${BPF_CAPSULE_LLVM_MAJOR} clang
    HINTS "${BPF_CAPSULE_LLVM_BIN_DIR}" REQUIRED
)
find_program(
    BPF_CAPSULE_OPT
    NAMES opt
    PATHS "${BPF_CAPSULE_LLVM_BIN_DIR}"
    NO_DEFAULT_PATH REQUIRED
)
find_program(
    BPF_CAPSULE_LLVM_LINK
    NAMES llvm-link
    PATHS "${BPF_CAPSULE_LLVM_BIN_DIR}"
    NO_DEFAULT_PATH REQUIRED
)
find_program(
    BPF_CAPSULE_LLVM_AR
    NAMES llvm-ar
    PATHS "${BPF_CAPSULE_LLVM_BIN_DIR}"
    NO_DEFAULT_PATH REQUIRED
)
find_program(
    BPF_CAPSULE_LLVM_OBJCOPY
    NAMES llvm-objcopy
    PATHS "${BPF_CAPSULE_LLVM_BIN_DIR}"
    NO_DEFAULT_PATH REQUIRED
)
find_program(
    BPF_CAPSULE_LLVM_OBJDUMP
    NAMES llvm-objdump
    PATHS "${BPF_CAPSULE_LLVM_BIN_DIR}"
    NO_DEFAULT_PATH REQUIRED
)
find_program(
    BPF_CAPSULE_LLVM_READELF
    NAMES llvm-readelf
    PATHS "${BPF_CAPSULE_LLVM_BIN_DIR}"
    NO_DEFAULT_PATH REQUIRED
)

execute_process(
    COMMAND "${BPF_CAPSULE_CLANG}" --version
    OUTPUT_VARIABLE bpf_capsule_clang_version
    OUTPUT_STRIP_TRAILING_WHITESPACE
)
string(REGEX MATCH "clang version ([0-9]+)" _ "${bpf_capsule_clang_version}")
if(NOT "${CMAKE_MATCH_1}" STREQUAL "${BPF_CAPSULE_LLVM_MAJOR}")
    message(FATAL_ERROR "LLVM tool mismatch: llc ${BPF_CAPSULE_LLVM_MAJOR}, "
                        "clang ${CMAKE_MATCH_1} (${BPF_CAPSULE_CLANG})"
    )
endif()

execute_process(
    COMMAND "${BPF_CAPSULE_OPT}" --version
    RESULT_VARIABLE bpf_capsule_opt_version_result
    OUTPUT_VARIABLE bpf_capsule_opt_version
    ERROR_VARIABLE bpf_capsule_opt_version_error
    OUTPUT_STRIP_TRAILING_WHITESPACE
)
string(REGEX MATCH "LLVM version ([0-9]+)" _ "${bpf_capsule_opt_version}")
if(NOT bpf_capsule_opt_version_result EQUAL 0 OR NOT "${CMAKE_MATCH_1}" STREQUAL
                                                 "${BPF_CAPSULE_LLVM_MAJOR}"
)
    message(
        FATAL_ERROR
            "LLVM tool mismatch: llc ${BPF_CAPSULE_LLVM_MAJOR}, but opt reports "
            "'${bpf_capsule_opt_version}${bpf_capsule_opt_version_error}' " "(${BPF_CAPSULE_OPT})"
    )
endif()

# The installed package config bakes in the LLVM major the pass plugin was
# built against. The plugin cannot load into another major's opt/llc, so
# reject a mismatched toolchain at configure time instead.
if(BPF_CAPSULE_REQUIRED_LLVM_MAJOR AND NOT BPF_CAPSULE_LLVM_MAJOR STREQUAL
                                       BPF_CAPSULE_REQUIRED_LLVM_MAJOR
)
    message(
        FATAL_ERROR
            "The installed BPF Capsule pass plugin was built against LLVM "
            "${BPF_CAPSULE_REQUIRED_LLVM_MAJOR}, but the discovered tools are "
            "LLVM ${BPF_CAPSULE_LLVM_MAJOR} (${BPF_CAPSULE_LLVM_BIN_DIR}). "
            "Put LLVM ${BPF_CAPSULE_REQUIRED_LLVM_MAJOR}'s llc first on PATH or "
            "configure with -DBPF_CAPSULE_LLC=/path/to/llvm-"
            "${BPF_CAPSULE_REQUIRED_LLVM_MAJOR}/bin/llc."
    )
endif()

message(STATUS "BPF Capsule LLVM ${BPF_CAPSULE_LLVM_MAJOR}: ${BPF_CAPSULE_LLVM_BIN_DIR}")
message(STATUS "BPF Capsule clang: ${BPF_CAPSULE_CLANG}")

# This is the only compatibility choice exposed by the compiler. It selects a
# complete, tested target profile; applications do not tune pass order or
# verifier workarounds. Stack and fiber ceilings below are build-time ABI
# bounds, distinct from the capacities selected before load.
set(BPF_CAPSULE_TARGET_KERNEL
    "5.15"
    CACHE STRING "Oldest Linux kernel on which generated BPF must load"
)
if(NOT BPF_CAPSULE_TARGET_KERNEL MATCHES "^([0-9]+)\\.([0-9]+)$")
    message(FATAL_ERROR "BPF_CAPSULE_TARGET_KERNEL must be a major.minor Linux version, got "
                        "${BPF_CAPSULE_TARGET_KERNEL}"
    )
endif()
set(_BPF_CAPSULE_TARGET_KERNEL_MAJOR "${CMAKE_MATCH_1}")
set(_BPF_CAPSULE_TARGET_KERNEL_MINOR "${CMAKE_MATCH_2}")
if(_BPF_CAPSULE_TARGET_KERNEL_MINOR GREATER_EQUAL 1000 OR BPF_CAPSULE_TARGET_KERNEL VERSION_LESS
                                                          "5.15"
)
    message(FATAL_ERROR "BPF_CAPSULE_TARGET_KERNEL must be Linux 5.15 or newer, got "
                        "${BPF_CAPSULE_TARGET_KERNEL}"
    )
endif()
math(EXPR _BPF_CAPSULE_RUNTIME_TARGET
     "${_BPF_CAPSULE_TARGET_KERNEL_MAJOR} * 1000 + ${_BPF_CAPSULE_TARGET_KERNEL_MINOR}"
)

if(BPF_CAPSULE_TARGET_KERNEL VERSION_LESS "6.6")
    set(_BPF_CAPSULE_CPU v3)
else()
    set(_BPF_CAPSULE_CPU v4)
endif()
if(BPF_CAPSULE_TARGET_KERNEL VERSION_GREATER_EQUAL "6.9")
    set(BPF_CAPSULE_HAS_ARENA TRUE)
else()
    set(BPF_CAPSULE_HAS_ARENA FALSE)
endif()
message(STATUS "BPF Capsule target: Linux ${BPF_CAPSULE_TARGET_KERNEL} (BPF ${_BPF_CAPSULE_CPU})")

# Linux accounts the complete BPF-to-BPF call chain in 32-byte units. Arena
# accesses need five non-step frames, leaving 352 native bytes for a generated
# step. Fixed-map accesses can add the outlined array-map accessor as a sixth
# frame, leaving 320. The late machine pass relocates excess spills into that
# function's fiber frame. This is a compiler invariant, not an application
# capacity knob.
if(BPF_CAPSULE_HAS_ARENA)
    set(_BPF_CAPSULE_NATIVE_STACK_BYTES 352)
else()
    set(_BPF_CAPSULE_NATIVE_STACK_BYTES 320)
endif()

set(BPF_CAPSULE_FIBER_STACK_BYTES
    262144
    CACHE STRING "Bytes in each Capsule unified fiber stack"
)
math(EXPR _bpf_capsule_stack_power_test
     "${BPF_CAPSULE_FIBER_STACK_BYTES} & (${BPF_CAPSULE_FIBER_STACK_BYTES} - 1)"
)
if(BPF_CAPSULE_FIBER_STACK_BYTES LESS 1
   OR BPF_CAPSULE_FIBER_STACK_BYTES GREATER 2097152
   OR NOT _bpf_capsule_stack_power_test EQUAL 0
)
    message(FATAL_ERROR "BPF_CAPSULE_FIBER_STACK_BYTES must be a power of two from 1 to 2097152")
endif()
message(STATUS "BPF Capsule unified fiber stack: ${BPF_CAPSULE_FIBER_STACK_BYTES} bytes")

# Empty keeps the public header's default. Setting this cache entry gives every
# input in the linked Capsule object the same explicit verifier/control
# ceiling; the active count is always chosen by the host before load.
set(BPF_CAPSULE_MAX_FIBERS
    ""
    CACHE STRING "compiled fiber ceiling; empty uses the runtime header default"
)
if(BPF_CAPSULE_MAX_FIBERS AND (NOT BPF_CAPSULE_MAX_FIBERS MATCHES "^[1-9][0-9]*$"
                               OR BPF_CAPSULE_MAX_FIBERS GREATER 65535)
)
    message(FATAL_ERROR "BPF_CAPSULE_MAX_FIBERS must be an integer from 1 to 65535 or empty, got "
                        "${BPF_CAPSULE_MAX_FIBERS}"
    )
endif()

if(NOT BPF_CAPSULE_PASS_TARGET)
    set(BPF_CAPSULE_PASS_TARGET bpf_capsule_pass)
endif()
if(NOT BPF_CAPSULE_INCLUDE_DIRS)
    get_filename_component(BPF_CAPSULE_SOURCE_ROOT "${CMAKE_CURRENT_LIST_DIR}/.." ABSOLUTE)
    set(BPF_CAPSULE_INCLUDE_DIRS
        "${BPF_CAPSULE_SOURCE_ROOT}/src/runtime/guest"
        "${BPF_CAPSULE_SOURCE_ROOT}/src/runtime/host" "${BPF_CAPSULE_SOURCE_ROOT}/src/runtime/abi"
    )
endif()
if(NOT BPF_CAPSULE_LIBC_DIR)
    get_filename_component(BPF_CAPSULE_LIBC_DIR "${CMAKE_CURRENT_LIST_DIR}/../src/libc" ABSOLUTE)
endif()
if(NOT BPF_CAPSULE_RUNTIME_DIR)
    get_filename_component(
        BPF_CAPSULE_RUNTIME_DIR "${CMAKE_CURRENT_LIST_DIR}/../src/runtime/guest" ABSOLUTE
    )
endif()
if(NOT BPF_CAPSULE_RUST_RUNTIME_DIR)
    get_filename_component(
        BPF_CAPSULE_RUST_RUNTIME_DIR "${CMAKE_CURRENT_LIST_DIR}/../src/rust/bpf-capsule-rt"
        ABSOLUTE
    )
endif()

# The unwrapped BPF Clang does not receive include roots from the host compiler
# wrapper. Preserve the roots CMake discovered for the source language; among
# other things, this supplies Linux UAPI headers in a Nix environment.
function(_bpf_capsule_implicit_include_flags out_var language)
    set(flags)
    foreach(directory IN LISTS CMAKE_${language}_IMPLICIT_INCLUDE_DIRECTORIES)
        if(IS_ABSOLUTE "${directory}" AND IS_DIRECTORY "${directory}")
            list(APPEND flags -isystem${directory})
        endif()
    endforeach()
    set(${out_var}
        ${flags}
        PARENT_SCOPE
    )
endfunction()

# Complete compiler-owned flags for a freestanding Clang input. C and C++ use
# the same BPF backend but have different implicit header roots; preserve the
# language CMake assigned to each source rather than making projects flatten
# everything into one hand-built flag list. C++ always uses the supported
# no-exceptions/no-RTTI subset; CXX_OPTIONS remains available for additional
# project-specific switches.
function(_bpf_capsule_compile_flags out_var language)
    set(flags
        -target
        bpf
        -mcpu=${_BPF_CAPSULE_CPU}
        -DBPF_CAPSULE_TARGET_KERNEL=${_BPF_CAPSULE_RUNTIME_TARGET}
        -DBPF_CAPSULE_FIBER_STACK_BYTES=${BPF_CAPSULE_FIBER_STACK_BYTES}
        -nostdlib
        -ffreestanding
        -fno-builtin
        -fno-asynchronous-unwind-tables
        -fno-unwind-tables
        -fno-unroll-loops
        -Wno-option-ignored
        -Wno-unused-command-line-argument
        -Wno-deprecated-non-prototype
        -O2
        -Xclang
        -disable-llvm-passes
        -mllvm
        -bpf-stack-size=512
        -flto
    )
    foreach(directory IN LISTS BPF_CAPSULE_INCLUDE_DIRS)
        list(APPEND flags -I${directory})
    endforeach()
    if(BPF_CAPSULE_MAX_FIBERS)
        list(APPEND flags -DBPF_CAPSULE_MAX_FIBERS=${BPF_CAPSULE_MAX_FIBERS})
    endif()
    if(language STREQUAL "CXX")
        # The Capsule runtime does not yet implement C++ unwinding or RTTI.
        # Make every CMake-managed C++ guest use the supported freestanding
        # subset instead of relying on each caller to remember these flags.
        list(APPEND flags -fno-exceptions -fno-rtti)
    endif()
    if(CMAKE_${language}_STANDARD)
        if(language STREQUAL "CXX")
            set(standard_prefix "c++")
            if(NOT DEFINED CMAKE_CXX_EXTENSIONS OR CMAKE_CXX_EXTENSIONS)
                set(standard_prefix "gnu++")
            endif()
        else()
            set(standard_prefix "c")
            if(NOT DEFINED CMAKE_C_EXTENSIONS OR CMAKE_C_EXTENSIONS)
                set(standard_prefix "gnu")
            endif()
        endif()
        list(APPEND flags -std=${standard_prefix}${CMAKE_${language}_STANDARD})
    endif()
    _bpf_capsule_implicit_include_flags(implicit_include_flags ${language})
    list(APPEND flags ${implicit_include_flags})
    set(${out_var}
        ${flags}
        PARENT_SCOPE
    )
endfunction()

# Compile CMake-managed C or C++ sources directly to bitcode. The host compiler
# wrapper is deliberately bypassed because injected host flags are invalid for
# BPF. COMPILE_OPTIONS applies to every source; C_OPTIONS and CXX_OPTIONS add
# language-specific switches such as -fno-exceptions and -fno-rtti.
function(bpf_capsule_bitcode out_var)
    cmake_parse_arguments(
        ARG
        ""
        ""
        "SOURCES;DEPENDS;INCLUDE_DIRECTORIES;COMPILE_DEFINITIONS;COMPILE_OPTIONS;C_OPTIONS;CXX_OPTIONS"
        ${ARGN}
    )
    if(ARG_UNPARSED_ARGUMENTS)
        message(
            FATAL_ERROR
                "bpf_capsule_bitcode(${out_var}) received unknown arguments: ${ARG_UNPARSED_ARGUMENTS}"
        )
    endif()
    if(NOT ARG_SOURCES)
        message(FATAL_ERROR "bpf_capsule_bitcode(${out_var}) needs SOURCES")
    endif()

    if(NOT BPF_CAPSULE_LIBBPF_TARGET)
        message(
            FATAL_ERROR
                "Set BPF_CAPSULE_LIBBPF_TARGET to the imported CMake target that supplies libbpf headers"
        )
    endif()
    if(NOT TARGET ${BPF_CAPSULE_LIBBPF_TARGET})
        message(
            FATAL_ERROR
                "BPF_CAPSULE_LIBBPF_TARGET does not name a target: ${BPF_CAPSULE_LIBBPF_TARGET}"
        )
    endif()
    set(include_directories ${ARG_INCLUDE_DIRECTORIES})
    get_target_property(
        libbpf_include_directories ${BPF_CAPSULE_LIBBPF_TARGET} INTERFACE_INCLUDE_DIRECTORIES
    )
    if(libbpf_include_directories AND NOT libbpf_include_directories MATCHES "-NOTFOUND$")
        list(APPEND include_directories ${libbpf_include_directories})
    endif()

    set(project_flags ${ARG_COMPILE_OPTIONS})
    foreach(directory IN LISTS include_directories)
        list(APPEND project_flags -I${directory})
    endforeach()
    foreach(definition IN LISTS ARG_COMPILE_DEFINITIONS)
        if(definition MATCHES "^-D")
            list(APPEND project_flags ${definition})
        else()
            list(APPEND project_flags -D${definition})
        endif()
    endforeach()

    set(outputs)
    foreach(source IN LISTS ARG_SOURCES)
        if(IS_ABSOLUTE "${source}")
            cmake_path(NORMAL_PATH source OUTPUT_VARIABLE absolute_source)
        else()
            cmake_path(
                ABSOLUTE_PATH
                source
                BASE_DIRECTORY
                "${CMAKE_CURRENT_SOURCE_DIR}"
                NORMALIZE
                OUTPUT_VARIABLE
                absolute_source
            )
        endif()
        get_source_file_property(language "${source}" LANGUAGE)
        if(NOT language OR language STREQUAL "NOTFOUND")
            get_filename_component(extension "${source}" LAST_EXT)
            string(REGEX REPLACE "^\\." "" extension "${extension}")
            if(extension IN_LIST CMAKE_CXX_SOURCE_FILE_EXTENSIONS)
                set(language CXX)
            elseif(extension IN_LIST CMAKE_C_SOURCE_FILE_EXTENSIONS)
                set(language C)
            else()
                message(
                    FATAL_ERROR "bpf_capsule_bitcode: cannot infer CMake language for ${source}"
                )
            endif()
        endif()
        if(NOT language STREQUAL "C" AND NOT language STREQUAL "CXX")
            message(
                FATAL_ERROR
                    "bpf_capsule_bitcode: ${source} uses unsupported CMake language ${language}; expected C or CXX"
            )
        endif()
        if(language STREQUAL "CXX" AND NOT CMAKE_CXX_COMPILER_LOADED)
            message(
                FATAL_ERROR
                    "bpf_capsule_bitcode: ${source} is C++, but this project has not enabled CXX"
            )
        endif()

        _bpf_capsule_compile_flags(compiler_flags ${language})
        set(source_flags ${project_flags})
        if(language STREQUAL "CXX")
            list(APPEND source_flags ${ARG_CXX_OPTIONS})
        else()
            list(APPEND source_flags ${ARG_C_OPTIONS})
        endif()

        get_filename_component(name "${source}" NAME_WE)
        # The same translation unit may legitimately be compiled into several
        # variants in one binary directory. The complete effective command,
        # not only its path, identifies the output; otherwise CMake silently
        # aliases e.g. allocator-enabled and null-allocator bitcode.
        string(MD5 source_id "${absolute_source};${language};${compiler_flags};${source_flags}")
        string(SUBSTRING "${source_id}" 0 8 source_id)
        set(bitcode "${CMAKE_CURRENT_BINARY_DIR}/bc/${name}-${source_id}.bc")
        set(depfile "${bitcode}.d")
        add_custom_command(
            OUTPUT "${bitcode}"
            COMMAND ${CMAKE_COMMAND} -E make_directory "${CMAKE_CURRENT_BINARY_DIR}/bc"
            COMMAND
                ${CMAKE_COMMAND} -E env NIX_CFLAGS_COMPILE= NIX_CFLAGS_LINK= "${BPF_CAPSULE_CLANG}"
                ${compiler_flags} ${source_flags} -MD -MF "${depfile}" -MT "${bitcode}" -c
                "${absolute_source}" -o "${bitcode}"
            DEPENDS "${absolute_source}" ${ARG_DEPENDS}
            DEPFILE "${depfile}"
            COMMENT "BPF bitcode: ${name}"
            VERBATIM
        )
        list(APPEND outputs "${bitcode}")
    endforeach()
    set(${out_var}
        ${outputs}
        PARENT_SCOPE
    )
endfunction()

# Compile one complete Cargo graph for Rust's freestanding BPF target and
# normalize the staticlib archive into a single LLVM module. The returned list
# also contains the common Capsule compatibility runtime, including the shared
# TLSF allocator used by Rust's GlobalAlloc implementation.
function(bpf_capsule_rust_bitcode out_var)
    cmake_parse_arguments(
        ARG "LOCKED;NO_DEFAULT_FEATURES" "MANIFEST_PATH;PACKAGE" "FEATURES;DEPENDS;RUSTFLAGS"
        ${ARGN}
    )
    if(ARG_UNPARSED_ARGUMENTS)
        message(
            FATAL_ERROR
                "bpf_capsule_rust_bitcode(${out_var}) received unknown arguments: ${ARG_UNPARSED_ARGUMENTS}"
        )
    endif()
    if(NOT ARG_MANIFEST_PATH OR NOT ARG_PACKAGE)
        message(FATAL_ERROR "bpf_capsule_rust_bitcode(${out_var}) needs MANIFEST_PATH and PACKAGE")
    endif()
    get_filename_component(manifest "${ARG_MANIFEST_PATH}" ABSOLUTE)
    if(NOT EXISTS "${manifest}")
        message(FATAL_ERROR "Cargo manifest does not exist: ${manifest}")
    endif()
    find_program(BPF_CAPSULE_CARGO NAMES cargo REQUIRED)

    set(cargo_features ${ARG_FEATURES})
    list(SORT cargo_features)
    string(REPLACE ";" "," cargo_features_argument "${ARG_FEATURES}")
    set(cargo_metadata_arguments metadata --format-version=1 --manifest-path "${manifest}")
    if(ARG_FEATURES)
        list(APPEND cargo_metadata_arguments --features "${cargo_features_argument}")
    endif()
    if(ARG_LOCKED)
        list(APPEND cargo_metadata_arguments --locked)
    endif()
    if(ARG_NO_DEFAULT_FEATURES)
        list(APPEND cargo_metadata_arguments --no-default-features)
    endif()
    execute_process(
        COMMAND "${BPF_CAPSULE_CARGO}" ${cargo_metadata_arguments}
        RESULT_VARIABLE cargo_metadata_result
        OUTPUT_VARIABLE cargo_metadata
        ERROR_VARIABLE cargo_metadata_error
        OUTPUT_STRIP_TRAILING_WHITESPACE
    )
    if(NOT cargo_metadata_result EQUAL 0)
        message(FATAL_ERROR "cargo metadata failed for ${manifest}:\n${cargo_metadata_error}")
    endif()

    set(cargo_inputs "${manifest}")
    get_filename_component(manifest_directory "${manifest}" DIRECTORY)
    if(EXISTS "${manifest_directory}/Cargo.lock")
        list(APPEND cargo_inputs "${manifest_directory}/Cargo.lock")
    endif()
    string(JSON package_count LENGTH "${cargo_metadata}" packages)
    if(package_count GREATER 0)
        math(EXPR package_last "${package_count} - 1")
        foreach(index RANGE 0 ${package_last})
            string(
                JSON
                source_type
                TYPE
                "${cargo_metadata}"
                packages
                ${index}
                source
            )
            if(NOT source_type STREQUAL "NULL")
                continue()
            endif()
            string(
                JSON
                package_manifest
                GET
                "${cargo_metadata}"
                packages
                ${index}
                manifest_path
            )
            get_filename_component(package_directory "${package_manifest}" DIRECTORY)
            file(GLOB_RECURSE package_inputs CONFIGURE_DEPENDS "${package_directory}/*.rs"
                 "${package_directory}/Cargo.toml"
            )
            list(APPEND cargo_inputs ${package_inputs})
        endforeach()
    endif()
    list(REMOVE_DUPLICATES cargo_inputs)

    string(
        MD5 cargo_id
            "${manifest};${ARG_PACKAGE};${cargo_features};${ARG_LOCKED};${ARG_NO_DEFAULT_FEATURES};${ARG_RUSTFLAGS};${BPF_CAPSULE_LLVM_MAJOR}"
    )
    string(SUBSTRING "${cargo_id}" 0 8 cargo_id)
    string(REPLACE ";" "|" rustflags "${ARG_RUSTFLAGS}")
    set(cargo_bitcode "${CMAKE_CURRENT_BINARY_DIR}/bc/${ARG_PACKAGE}-${cargo_id}.bc")
    set(cargo_target_directory "${CMAKE_CURRENT_BINARY_DIR}/cargo/${ARG_PACKAGE}-${cargo_id}")
    add_custom_command(
        OUTPUT "${cargo_bitcode}"
        COMMAND
            "${CMAKE_COMMAND}" "-DBPF_CAPSULE_CARGO=${BPF_CAPSULE_CARGO}"
            "-DBPF_CAPSULE_LLVM_AR=${BPF_CAPSULE_LLVM_AR}"
            "-DBPF_CAPSULE_LLVM_LINK=${BPF_CAPSULE_LLVM_LINK}"
            "-DBPF_CAPSULE_CARGO_MANIFEST=${manifest}" "-DBPF_CAPSULE_CARGO_PACKAGE=${ARG_PACKAGE}"
            "-DBPF_CAPSULE_CARGO_FEATURES=${cargo_features_argument}"
            "-DBPF_CAPSULE_CARGO_LOCKED=${ARG_LOCKED}"
            "-DBPF_CAPSULE_CARGO_NO_DEFAULT_FEATURES=${ARG_NO_DEFAULT_FEATURES}"
            "-DBPF_CAPSULE_CARGO_TARGET_DIR=${cargo_target_directory}"
            "-DBPF_CAPSULE_RUSTFLAGS=${rustflags}" "-DBPF_CAPSULE_RUST_OUTPUT=${cargo_bitcode}" -P
            "${CMAKE_CURRENT_FUNCTION_LIST_DIR}/BuildRustBitcode.cmake"
        DEPENDS ${cargo_inputs} ${ARG_DEPENDS}
        COMMENT "Cargo bitcode: ${ARG_PACKAGE}"
        VERBATIM
    )

    if(NOT IS_DIRECTORY "${BPF_CAPSULE_LIBC_DIR}")
        message(FATAL_ERROR "BPF Capsule libc sources are unavailable: ${BPF_CAPSULE_LIBC_DIR}")
    endif()
    bpf_capsule_bitcode(
        rust_compatibility_bitcode
        SOURCES "${BPF_CAPSULE_LIBC_DIR}/freestanding.c" "${BPF_CAPSULE_LIBC_DIR}/tlsf.c"
                "${BPF_CAPSULE_LIBC_DIR}/int128.c" "${BPF_CAPSULE_LIBC_DIR}/softfloat.c"
                "${BPF_CAPSULE_LIBC_DIR}/mathfns.c"
        INCLUDE_DIRECTORIES "${BPF_CAPSULE_LIBC_DIR}" "${BPF_CAPSULE_LIBC_DIR}/include"
        COMPILE_OPTIONS -g
    )

    set(${out_var}
        "${cargo_bitcode}" ${rust_compatibility_bitcode}
        PARENT_SCOPE
    )
endfunction()

# Link bitcode, run the complete verifier-oriented transform, and invoke the
# stock LLVM backend with the late native-stack overflow pass. This function is
# intentionally the one path used by every full-program example.
# The Capsule runtime is toolchain business: every object links it
# automatically, so application code only ever includes bpf_capsule.h.
# COMPILE_DEFINITIONS forwards the runtime-geometry overrides
# (BPF_CAPSULE_MAX_FIBERS, BPF_CAPSULE_DRIVE_LEVEL, ...) a proof target selects; they
# must match the definitions its guest bitcode was compiled with. One
# compilation is shared per directory and definition set. Suite plumbing that
# links a bare bitcode by hand (a negative compiler contract, for instance)
# uses this directly.
function(bpf_capsule_runtime_bitcode out_var)
    cmake_parse_arguments(ARG "" "" "COMPILE_DEFINITIONS" ${ARGN})
    if(ARG_UNPARSED_ARGUMENTS)
        message(
            FATAL_ERROR
                "bpf_capsule_runtime_bitcode(${out_var}) received unknown arguments: ${ARG_UNPARSED_ARGUMENTS}"
        )
    endif()
    string(MD5 runtime_key "${ARG_COMPILE_DEFINITIONS}")
    get_property(
        runtime_bitcode
        DIRECTORY
        PROPERTY "BPF_CAPSULE_RUNTIME_BITCODE_${runtime_key}"
    )
    if(NOT runtime_bitcode)
        if(NOT EXISTS "${BPF_CAPSULE_RUNTIME_DIR}/bpf_capsule.c")
            message(
                FATAL_ERROR "BPF Capsule runtime source is unavailable: ${BPF_CAPSULE_RUNTIME_DIR}"
            )
        endif()
        bpf_capsule_bitcode(
            runtime_bitcode
            SOURCES "${BPF_CAPSULE_RUNTIME_DIR}/bpf_capsule.c"
            COMPILE_DEFINITIONS ${ARG_COMPILE_DEFINITIONS}
            COMPILE_OPTIONS -g
        )
        set_property(
            DIRECTORY PROPERTY "BPF_CAPSULE_RUNTIME_BITCODE_${runtime_key}" "${runtime_bitcode}"
        )
    endif()
    set(${out_var}
        "${runtime_bitcode}"
        PARENT_SCOPE
    )
endfunction()

function(bpf_capsule_object target)
    cmake_parse_arguments(
        ARG "" "OUTPUT;LINKED_BC;OPTIMIZED_BC" "BITCODE;DEPENDS;RUNTIME_COMPILE_DEFINITIONS"
        ${ARGN}
    )
    if(ARG_UNPARSED_ARGUMENTS)
        message(
            FATAL_ERROR
                "bpf_capsule_object(${target}) received unknown arguments: ${ARG_UNPARSED_ARGUMENTS}"
        )
    endif()
    if(NOT ARG_OUTPUT OR NOT ARG_BITCODE)
        message(FATAL_ERROR "bpf_capsule_object(${target}) needs OUTPUT and BITCODE")
    endif()
    bpf_capsule_runtime_bitcode(
        runtime_bitcode COMPILE_DEFINITIONS ${ARG_RUNTIME_COMPILE_DEFINITIONS}
    )
    list(APPEND ARG_BITCODE ${runtime_bitcode})
    if(NOT ARG_LINKED_BC)
        set(ARG_LINKED_BC "${target}-linked.bc")
    endif()
    if(NOT ARG_OPTIMIZED_BC)
        set(ARG_OPTIMIZED_BC "${target}-optimized.bc")
    endif()
    if(NOT TARGET ${BPF_CAPSULE_PASS_TARGET})
        message(FATAL_ERROR "BPF Capsule pass target '${BPF_CAPSULE_PASS_TARGET}' is unavailable")
    endif()

    add_custom_command(
        OUTPUT "${ARG_OUTPUT}"
        COMMAND "${BPF_CAPSULE_LLVM_LINK}" -o "${ARG_LINKED_BC}" ${ARG_BITCODE}
        COMMAND
            "${BPF_CAPSULE_OPT}" -load-pass-plugin=$<TARGET_FILE:${BPF_CAPSULE_PASS_TARGET}>
            --disable-loop-unrolling -bpf-target=${BPF_CAPSULE_TARGET_KERNEL}
            -bpf-fiber-stack-size=${BPF_CAPSULE_FIBER_STACK_BYTES} --passes=bpf-capsule
            "${ARG_LINKED_BC}" -o "${ARG_OPTIMIZED_BC}"
        COMMAND
            "${BPF_CAPSULE_LLC}" -O2 -mcpu=${_BPF_CAPSULE_CPU} -load
            $<TARGET_FILE:${BPF_CAPSULE_PASS_TARGET}> -bpf-target=${BPF_CAPSULE_TARGET_KERNEL}
            -bpf-unified-spill-pipeline -bpf-unified-spill-limit=${_BPF_CAPSULE_NATIVE_STACK_BYTES}
            # Let the post-RA Capsule pass inspect and relocate large physical
            # frames. It independently rejects non-Capsule functions above the
            # kernel's real 512-byte native limit.
            --bpf-stack-size=${BPF_CAPSULE_FIBER_STACK_BYTES} -verify-machineinstrs -filetype=obj -o
            "${ARG_OUTPUT}.with-unwind" "${ARG_OPTIMIZED_BC}"
        # LLVM 22 emits an unusable .eh_frame even though every generated BPF
        # function is nounwind. libbpf correctly ignores it but logs a warning
        # for every object open; remove only that metadata before skeleton
        # generation. Code, BTF and relocations remain stock LLVM output.
        COMMAND "${BPF_CAPSULE_LLVM_OBJCOPY}" --remove-section=.eh_frame "${ARG_OUTPUT}.with-unwind"
                "${ARG_OUTPUT}"
        COMMAND "${CMAKE_COMMAND}" -E rm -f "${ARG_OUTPUT}.with-unwind"
        DEPENDS ${ARG_BITCODE} ${ARG_DEPENDS} ${BPF_CAPSULE_PASS_TARGET}
        COMMAND_EXPAND_LISTS VERBATIM
    )
    add_custom_target(${target} DEPENDS "${ARG_OUTPUT}")
endfunction()

# Generate a stock libbpf skeleton from a finished Capsule object. The header
# embeds the ELF, so applications ship and open one native executable; the raw
# object remains a build artifact useful to compiler tests and inspection.
function(bpf_capsule_skeleton target)
    cmake_parse_arguments(ARG "" "OUTPUT;OBJECT;NAME" "DEPENDS" ${ARGN})
    if(ARG_UNPARSED_ARGUMENTS)
        message(
            FATAL_ERROR
                "bpf_capsule_skeleton(${target}) received unknown arguments: ${ARG_UNPARSED_ARGUMENTS}"
        )
    endif()
    if(NOT ARG_OUTPUT
       OR NOT ARG_OBJECT
       OR NOT ARG_NAME
    )
        message(FATAL_ERROR "bpf_capsule_skeleton(${target}) needs OUTPUT, OBJECT, and NAME")
    endif()
    find_program(BPF_CAPSULE_BPFTOOL NAMES bpftool REQUIRED)
    add_custom_command(
        OUTPUT "${ARG_OUTPUT}"
        COMMAND
            "${CMAKE_COMMAND}" "-DBPF_CAPSULE_BPFTOOL=${BPF_CAPSULE_BPFTOOL}"
            "-DBPF_CAPSULE_SKELETON_INPUT=${ARG_OBJECT}"
            "-DBPF_CAPSULE_SKELETON_OUTPUT=${ARG_OUTPUT}" "-DBPF_CAPSULE_SKELETON_NAME=${ARG_NAME}"
            -P "${CMAKE_CURRENT_FUNCTION_LIST_DIR}/GenerateSkeleton.cmake"
        DEPENDS "${ARG_OBJECT}" ${ARG_DEPENDS}
        COMMENT "libbpf skeleton: ${ARG_NAME}"
        VERBATIM
    )
    set_source_files_properties("${ARG_OUTPUT}" PROPERTIES GENERATED TRUE)
    add_custom_target(${target} DEPENDS "${ARG_OUTPUT}")
endfunction()
