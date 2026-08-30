# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
# Public CMake integration for the bpf-capsule-cc / bpf-capsule-ld toolchain.
include_guard(GLOBAL)

set(BPF_CAPSULE_TARGET_KERNEL "6.9" CACHE STRING
    "Oldest Linux kernel on which generated BPF must load")
if(NOT BPF_CAPSULE_TARGET_KERNEL MATCHES "^([0-9]+)\\.([0-9]+)$")
    message(FATAL_ERROR
        "BPF_CAPSULE_TARGET_KERNEL must be a major.minor Linux version, got ${BPF_CAPSULE_TARGET_KERNEL}")
endif()
set(_BPF_CAPSULE_KERNEL_MAJOR "${CMAKE_MATCH_1}")
set(_BPF_CAPSULE_KERNEL_MINOR "${CMAKE_MATCH_2}")
if(_BPF_CAPSULE_KERNEL_MINOR GREATER_EQUAL 1000 OR
   BPF_CAPSULE_TARGET_KERNEL VERSION_LESS "5.15")
    message(FATAL_ERROR
        "BPF_CAPSULE_TARGET_KERNEL must be Linux 5.15 or newer, got ${BPF_CAPSULE_TARGET_KERNEL}")
endif()
if(BPF_CAPSULE_TARGET_KERNEL VERSION_GREATER_EQUAL "6.9")
    set(BPF_CAPSULE_HAS_ARENA TRUE)
else()
    set(BPF_CAPSULE_HAS_ARENA FALSE)
endif()

set(BPF_CAPSULE_FIBER_STACK_BYTES 262144 CACHE STRING
    "Bytes in each Capsule fiber stack")
math(EXPR _bpf_capsule_stack_power
    "${BPF_CAPSULE_FIBER_STACK_BYTES} & (${BPF_CAPSULE_FIBER_STACK_BYTES} - 1)")
if(BPF_CAPSULE_FIBER_STACK_BYTES LESS 1 OR
   BPF_CAPSULE_FIBER_STACK_BYTES GREATER 2097152 OR
   NOT _bpf_capsule_stack_power EQUAL 0)
    message(FATAL_ERROR
        "BPF_CAPSULE_FIBER_STACK_BYTES must be a power of two from 1 to 2097152")
endif()

set(BPF_CAPSULE_MAX_FIBERS "" CACHE STRING
    "Compiled fiber ceiling; empty uses the runtime default")
if(BPF_CAPSULE_MAX_FIBERS AND
   (NOT BPF_CAPSULE_MAX_FIBERS MATCHES "^[1-9][0-9]*$" OR
    BPF_CAPSULE_MAX_FIBERS GREATER 65535))
    message(FATAL_ERROR
        "BPF_CAPSULE_MAX_FIBERS must be an integer from 1 to 65535 or empty, got ${BPF_CAPSULE_MAX_FIBERS}")
endif()

if(NOT BPF_CAPSULE_CC_TARGET)
    set(BPF_CAPSULE_CC_TARGET bpf-capsule-cc)
endif()
if(NOT BPF_CAPSULE_LD_TARGET)
    set(BPF_CAPSULE_LD_TARGET bpf-capsule-ld)
endif()
if(NOT TARGET ${BPF_CAPSULE_CC_TARGET} OR NOT TARGET ${BPF_CAPSULE_LD_TARGET})
    message(FATAL_ERROR "BPF Capsule compiler targets are unavailable")
endif()

if(NOT BPF_CAPSULE_INCLUDE_DIRS)
    get_filename_component(_bpf_capsule_root "${CMAKE_CURRENT_LIST_DIR}/.." ABSOLUTE)
    set(BPF_CAPSULE_INCLUDE_DIRS
        "${_bpf_capsule_root}/src/runtime/guest"
        "${_bpf_capsule_root}/src/runtime/host")
endif()
if(NOT BPF_CAPSULE_RUNTIME_DIR)
    get_filename_component(BPF_CAPSULE_RUNTIME_DIR
        "${CMAKE_CURRENT_LIST_DIR}/../src/runtime/guest" ABSOLUTE)
endif()
if(NOT BPF_CAPSULE_LIBC_DIR)
    get_filename_component(BPF_CAPSULE_LIBC_DIR
        "${CMAKE_CURRENT_LIST_DIR}/../src/libc" ABSOLUTE)
endif()
if(NOT BPF_CAPSULE_TLSF_DIR)
    get_filename_component(BPF_CAPSULE_TLSF_DIR
        "${CMAKE_CURRENT_LIST_DIR}/../thirdparty/tlsf" ABSOLUTE)
endif()
if(NOT BPF_CAPSULE_RUST_RUNTIME_DIR)
    get_filename_component(BPF_CAPSULE_RUST_RUNTIME_DIR
        "${CMAKE_CURRENT_LIST_DIR}/../src/rust/bpf-capsule-rt" ABSOLUTE)
endif()

# Compile C or C++ translation units into unoptimized BPF-target LLVM bitcode.
# The whole-program optimizer lives in bpf-capsule-ld, so consumers must not
# insert an independent opt/llc stage between these helpers.
function(bpf_capsule_bitcode out_var)
    cmake_parse_arguments(ARG "" ""
        "SOURCES;DEPENDS;INCLUDE_DIRECTORIES;COMPILE_DEFINITIONS;COMPILE_OPTIONS;C_OPTIONS;CXX_OPTIONS"
        ${ARGN})
    if(ARG_UNPARSED_ARGUMENTS)
        message(FATAL_ERROR
            "bpf_capsule_bitcode(${out_var}) received unknown arguments: ${ARG_UNPARSED_ARGUMENTS}")
    endif()
    if(NOT ARG_SOURCES)
        message(FATAL_ERROR "bpf_capsule_bitcode(${out_var}) needs SOURCES")
    endif()
    if(NOT BPF_CAPSULE_LIBBPF_TARGET OR NOT TARGET ${BPF_CAPSULE_LIBBPF_TARGET})
        message(FATAL_ERROR
            "Set BPF_CAPSULE_LIBBPF_TARGET to the imported target that supplies libbpf headers")
    endif()

    set(common_flags ${ARG_COMPILE_OPTIONS})
    # The freestanding allocator glue includes the vendored "tlsf.h".
    list(APPEND common_flags "-I${BPF_CAPSULE_TLSF_DIR}")
    foreach(directory IN LISTS ARG_INCLUDE_DIRECTORIES)
        list(APPEND common_flags "-I${directory}")
    endforeach()
    get_target_property(_bpf_capsule_libbpf_includes
        ${BPF_CAPSULE_LIBBPF_TARGET} INTERFACE_INCLUDE_DIRECTORIES)
    if(_bpf_capsule_libbpf_includes AND
       NOT _bpf_capsule_libbpf_includes MATCHES "-NOTFOUND$")
        foreach(directory IN LISTS _bpf_capsule_libbpf_includes)
            if(NOT directory MATCHES "^\\$<")
                list(APPEND common_flags "-isystem${directory}")
            endif()
        endforeach()
    endif()
    foreach(directory IN LISTS CMAKE_C_IMPLICIT_INCLUDE_DIRECTORIES)
        if(IS_ABSOLUTE "${directory}" AND IS_DIRECTORY "${directory}")
            list(APPEND common_flags "-isystem${directory}")
        endif()
    endforeach()
    foreach(definition IN LISTS ARG_COMPILE_DEFINITIONS)
        if(definition MATCHES "^-D")
            list(APPEND common_flags "${definition}")
        else()
            list(APPEND common_flags "-D${definition}")
        endif()
    endforeach()
    if(BPF_CAPSULE_MAX_FIBERS)
        list(APPEND common_flags "-DBPF_CAPSULE_MAX_FIBERS=${BPF_CAPSULE_MAX_FIBERS}")
    endif()

    set(outputs)
    foreach(source IN LISTS ARG_SOURCES)
        cmake_path(ABSOLUTE_PATH source BASE_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
                   NORMALIZE OUTPUT_VARIABLE absolute_source)
        get_source_file_property(language "${source}" LANGUAGE)
        if(NOT language OR language STREQUAL "NOTFOUND")
            get_filename_component(extension "${source}" LAST_EXT)
            string(REGEX REPLACE "^\\." "" extension "${extension}")
            if(extension IN_LIST CMAKE_CXX_SOURCE_FILE_EXTENSIONS)
                set(language CXX)
            elseif(extension IN_LIST CMAKE_C_SOURCE_FILE_EXTENSIONS)
                set(language C)
            else()
                message(FATAL_ERROR "bpf_capsule_bitcode: cannot infer language for ${source}")
            endif()
        endif()
        if(NOT language STREQUAL "C" AND NOT language STREQUAL "CXX")
            message(FATAL_ERROR
                "bpf_capsule_bitcode: ${source} uses unsupported language ${language}")
        endif()

        set(source_flags ${common_flags})
        if(language STREQUAL "CXX")
            list(APPEND source_flags -fno-exceptions -fno-rtti ${ARG_CXX_OPTIONS})
        else()
            list(APPEND source_flags ${ARG_C_OPTIONS})
        endif()
        get_filename_component(name "${source}" NAME_WE)
        string(MD5 source_id "${absolute_source};${language};${source_flags}")
        string(SUBSTRING "${source_id}" 0 8 source_id)
        set(bitcode "${CMAKE_CURRENT_BINARY_DIR}/bc/${name}-${source_id}.bc")
        add_custom_command(
            OUTPUT "${bitcode}"
            COMMAND ${CMAKE_COMMAND} -E make_directory "${CMAKE_CURRENT_BINARY_DIR}/bc"
            COMMAND $<TARGET_FILE:${BPF_CAPSULE_CC_TARGET}>
                --kernel "${BPF_CAPSULE_TARGET_KERNEL}"
                --fiber-stack "${BPF_CAPSULE_FIBER_STACK_BYTES}"
                ${source_flags} -MD -MF "${bitcode}.d" -MT "${bitcode}"
                -c "${absolute_source}" -o "${bitcode}"
            DEPENDS ${BPF_CAPSULE_CC_TARGET} "${absolute_source}" ${ARG_DEPENDS}
            DEPFILE "${bitcode}.d"
            COMMENT "capsule-cc: ${name}"
            COMMAND_EXPAND_LISTS VERBATIM)
        list(APPEND outputs "${bitcode}")
    endforeach()
    set(${out_var} ${outputs} PARENT_SCOPE)
endfunction()

# Rust remains a Cargo language frontend. This helper turns Cargo's staticlib
# into one ordinary LLVM bitcode input; bpf-capsule-ld still owns every
# whole-program transform and all BPF code generation.
function(bpf_capsule_rust_bitcode out_var)
    cmake_parse_arguments(ARG "LOCKED;NO_DEFAULT_FEATURES" "MANIFEST_PATH;PACKAGE"
        "FEATURES;DEPENDS;RUSTFLAGS" ${ARGN})
    if(ARG_UNPARSED_ARGUMENTS)
        message(FATAL_ERROR
            "bpf_capsule_rust_bitcode(${out_var}) received unknown arguments: ${ARG_UNPARSED_ARGUMENTS}")
    endif()
    if(NOT ARG_MANIFEST_PATH OR NOT ARG_PACKAGE)
        message(FATAL_ERROR
            "bpf_capsule_rust_bitcode(${out_var}) needs MANIFEST_PATH and PACKAGE")
    endif()
    get_filename_component(manifest "${ARG_MANIFEST_PATH}" ABSOLUTE)
    if(NOT EXISTS "${manifest}")
        message(FATAL_ERROR "Cargo manifest does not exist: ${manifest}")
    endif()
    if(NOT BPF_CAPSULE_LLVM_MAJOR)
        message(FATAL_ERROR "BPF Capsule package did not declare its LLVM major")
    endif()

    find_program(BPF_CAPSULE_CARGO NAMES cargo REQUIRED)
    find_program(BPF_CAPSULE_LLVM_AR
        NAMES llvm-ar-${BPF_CAPSULE_LLVM_MAJOR} llvm-ar
        HINTS "${LLVM_TOOLS_BINARY_DIR}" REQUIRED)
    find_program(BPF_CAPSULE_LLVM_LINK
        NAMES llvm-link-${BPF_CAPSULE_LLVM_MAJOR} llvm-link
        HINTS "${LLVM_TOOLS_BINARY_DIR}" REQUIRED)
    foreach(tool IN ITEMS BPF_CAPSULE_LLVM_AR BPF_CAPSULE_LLVM_LINK)
        execute_process(COMMAND "${${tool}}" --version
            RESULT_VARIABLE tool_result OUTPUT_VARIABLE tool_version
            ERROR_VARIABLE tool_error OUTPUT_STRIP_TRAILING_WHITESPACE)
        string(REGEX MATCH "LLVM version ([0-9]+)" _ "${tool_version}")
        if(NOT tool_result EQUAL 0 OR
           NOT CMAKE_MATCH_1 STREQUAL BPF_CAPSULE_LLVM_MAJOR)
            message(FATAL_ERROR
                "${tool} must be LLVM ${BPF_CAPSULE_LLVM_MAJOR}; got ${${tool}}: ${tool_version}${tool_error}")
        endif()
    endforeach()

    set(cargo_features ${ARG_FEATURES})
    list(SORT cargo_features)
    string(REPLACE ";" "," cargo_features_argument "${cargo_features}")
    set(metadata_arguments metadata --format-version=1
        --manifest-path "${manifest}")
    if(cargo_features)
        list(APPEND metadata_arguments --features "${cargo_features_argument}")
    endif()
    if(ARG_LOCKED)
        list(APPEND metadata_arguments --locked)
    endif()
    if(ARG_NO_DEFAULT_FEATURES)
        list(APPEND metadata_arguments --no-default-features)
    endif()
    execute_process(COMMAND "${BPF_CAPSULE_CARGO}" ${metadata_arguments}
        RESULT_VARIABLE metadata_result OUTPUT_VARIABLE metadata
        ERROR_VARIABLE metadata_error OUTPUT_STRIP_TRAILING_WHITESPACE)
    if(NOT metadata_result EQUAL 0)
        message(FATAL_ERROR "cargo metadata failed for ${manifest}:\n${metadata_error}")
    endif()

    set(cargo_inputs "${manifest}")
    get_filename_component(manifest_directory "${manifest}" DIRECTORY)
    if(EXISTS "${manifest_directory}/Cargo.lock")
        list(APPEND cargo_inputs "${manifest_directory}/Cargo.lock")
    endif()
    string(JSON package_count LENGTH "${metadata}" packages)
    if(package_count GREATER 0)
        math(EXPR package_last "${package_count} - 1")
        foreach(index RANGE 0 ${package_last})
            string(JSON source_type TYPE "${metadata}" packages ${index} source)
            if(NOT source_type STREQUAL "NULL")
                continue()
            endif()
            string(JSON package_manifest GET "${metadata}" packages ${index} manifest_path)
            get_filename_component(package_directory "${package_manifest}" DIRECTORY)
            file(GLOB_RECURSE package_inputs CONFIGURE_DEPENDS
                "${package_directory}/*.rs" "${package_directory}/Cargo.toml")
            list(APPEND cargo_inputs ${package_inputs})
        endforeach()
    endif()
    list(REMOVE_DUPLICATES cargo_inputs)

    string(MD5 cargo_id
        "${manifest};${ARG_PACKAGE};${cargo_features};${ARG_LOCKED};${ARG_NO_DEFAULT_FEATURES};${ARG_RUSTFLAGS};${BPF_CAPSULE_LLVM_MAJOR}")
    string(SUBSTRING "${cargo_id}" 0 8 cargo_id)
    string(REPLACE ";" "|" rustflags "${ARG_RUSTFLAGS}")
    set(cargo_bitcode
        "${CMAKE_CURRENT_BINARY_DIR}/bc/${ARG_PACKAGE}-${cargo_id}.bc")
    set(cargo_target_directory
        "${CMAKE_CURRENT_BINARY_DIR}/cargo/${ARG_PACKAGE}-${cargo_id}")
    add_custom_command(
        OUTPUT "${cargo_bitcode}"
        COMMAND "${CMAKE_COMMAND}"
            "-DBPF_CAPSULE_CARGO=${BPF_CAPSULE_CARGO}"
            "-DBPF_CAPSULE_LLVM_AR=${BPF_CAPSULE_LLVM_AR}"
            "-DBPF_CAPSULE_LLVM_LINK=${BPF_CAPSULE_LLVM_LINK}"
            "-DBPF_CAPSULE_CARGO_MANIFEST=${manifest}"
            "-DBPF_CAPSULE_CARGO_PACKAGE=${ARG_PACKAGE}"
            "-DBPF_CAPSULE_CARGO_FEATURES=${cargo_features_argument}"
            "-DBPF_CAPSULE_CARGO_LOCKED=${ARG_LOCKED}"
            "-DBPF_CAPSULE_CARGO_NO_DEFAULT_FEATURES=${ARG_NO_DEFAULT_FEATURES}"
            "-DBPF_CAPSULE_CARGO_TARGET_DIR=${cargo_target_directory}"
            "-DBPF_CAPSULE_RUSTFLAGS=${rustflags}"
            "-DBPF_CAPSULE_RUST_OUTPUT=${cargo_bitcode}"
            -P "${CMAKE_CURRENT_FUNCTION_LIST_DIR}/BuildRustBitcode.cmake"
        DEPENDS ${cargo_inputs} ${ARG_DEPENDS}
        COMMENT "Cargo bitcode: ${ARG_PACKAGE}"
        VERBATIM)

    if(NOT IS_DIRECTORY "${BPF_CAPSULE_LIBC_DIR}")
        message(FATAL_ERROR
            "BPF Capsule libc sources are unavailable: ${BPF_CAPSULE_LIBC_DIR}")
    endif()
    bpf_capsule_bitcode(rust_compatibility_bitcode
        SOURCES "${BPF_CAPSULE_LIBC_DIR}/freestanding.c"
                "${BPF_CAPSULE_LIBC_DIR}/tlsf_capsule.c"
                "${BPF_CAPSULE_LIBC_DIR}/int128.c"
                "${BPF_CAPSULE_LIBC_DIR}/softfloat.c"
                "${BPF_CAPSULE_LIBC_DIR}/mathfns.c"
        INCLUDE_DIRECTORIES "${BPF_CAPSULE_LIBC_DIR}"
                            "${BPF_CAPSULE_LIBC_DIR}/include"
        COMPILE_OPTIONS -g)
    set(${out_var} "${cargo_bitcode}" ${rust_compatibility_bitcode} PARENT_SCOPE)
endfunction()

# Compile the object runtime once per directory and geometry definition set.
function(bpf_capsule_runtime_bitcode out_var)
    cmake_parse_arguments(ARG "" "" "COMPILE_DEFINITIONS" ${ARGN})
    if(ARG_UNPARSED_ARGUMENTS)
        message(FATAL_ERROR
            "bpf_capsule_runtime_bitcode(${out_var}) received unknown arguments: ${ARG_UNPARSED_ARGUMENTS}")
    endif()
    string(MD5 runtime_key "${ARG_COMPILE_DEFINITIONS}")
    get_property(runtime_bitcode DIRECTORY PROPERTY
        "BPF_CAPSULE_RUNTIME_BITCODE_${runtime_key}")
    if(NOT runtime_bitcode)
        set(runtime_source "${BPF_CAPSULE_RUNTIME_DIR}/bpf_capsule.c")
        if(NOT EXISTS "${runtime_source}")
            message(FATAL_ERROR "BPF Capsule runtime source is unavailable: ${runtime_source}")
        endif()
        bpf_capsule_bitcode(runtime_bitcode
            SOURCES "${runtime_source}"
            COMPILE_DEFINITIONS ${ARG_COMPILE_DEFINITIONS}
            COMPILE_OPTIONS -g)
        set_property(DIRECTORY PROPERTY
            "BPF_CAPSULE_RUNTIME_BITCODE_${runtime_key}" "${runtime_bitcode}")
    endif()
    set(${out_var} "${runtime_bitcode}" PARENT_SCOPE)
endfunction()

# Link a complete Capsule object. The runtime is always included here; a
# consumer provides only its own guest/library bitcode.
function(bpf_capsule_object target)
    cmake_parse_arguments(ARG "SAVE_TEMPS" "OUTPUT"
        "BITCODE;DEPENDS;RUNTIME_COMPILE_DEFINITIONS;LINK_OPTIONS" ${ARGN})
    if(ARG_UNPARSED_ARGUMENTS)
        message(FATAL_ERROR
            "bpf_capsule_object(${target}) received unknown arguments: ${ARG_UNPARSED_ARGUMENTS}")
    endif()
    if(NOT ARG_OUTPUT OR NOT ARG_BITCODE)
        message(FATAL_ERROR "bpf_capsule_object(${target}) needs OUTPUT and BITCODE")
    endif()
    cmake_path(ABSOLUTE_PATH ARG_OUTPUT BASE_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}"
               NORMALIZE OUTPUT_VARIABLE output)
    bpf_capsule_runtime_bitcode(runtime_bitcode
        COMPILE_DEFINITIONS ${ARG_RUNTIME_COMPILE_DEFINITIONS})
    set(save_temps)
    if(ARG_SAVE_TEMPS)
        set(save_temps --save-temps)
    endif()
    add_custom_command(
        OUTPUT "${output}"
        COMMAND $<TARGET_FILE:${BPF_CAPSULE_LD_TARGET}>
            --kernel "${BPF_CAPSULE_TARGET_KERNEL}"
            --fiber-stack "${BPF_CAPSULE_FIBER_STACK_BYTES}"
            ${ARG_LINK_OPTIONS} ${save_temps} -o "${output}"
            ${ARG_BITCODE} ${runtime_bitcode}
        DEPENDS ${BPF_CAPSULE_LD_TARGET} ${ARG_BITCODE} ${runtime_bitcode} ${ARG_DEPENDS}
        COMMENT "capsule-ld: ${target}"
        COMMAND_EXPAND_LISTS VERBATIM)
    add_custom_target(${target} DEPENDS "${output}")
endfunction()

function(bpf_capsule_skeleton target)
    cmake_parse_arguments(ARG "" "OUTPUT;OBJECT;NAME" "DEPENDS" ${ARGN})
    if(ARG_UNPARSED_ARGUMENTS)
        message(FATAL_ERROR
            "bpf_capsule_skeleton(${target}) received unknown arguments: ${ARG_UNPARSED_ARGUMENTS}")
    endif()
    if(NOT ARG_OUTPUT OR NOT ARG_OBJECT OR NOT ARG_NAME)
        message(FATAL_ERROR
            "bpf_capsule_skeleton(${target}) needs OUTPUT, OBJECT, and NAME")
    endif()
    find_program(BPF_CAPSULE_BPFTOOL NAMES bpftool REQUIRED)
    cmake_path(ABSOLUTE_PATH ARG_OUTPUT BASE_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}"
               NORMALIZE OUTPUT_VARIABLE output)
    cmake_path(ABSOLUTE_PATH ARG_OBJECT BASE_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}"
               NORMALIZE OUTPUT_VARIABLE object)
    add_custom_command(
        OUTPUT "${output}"
        COMMAND "${CMAKE_COMMAND}" "-DBPF_CAPSULE_BPFTOOL=${BPF_CAPSULE_BPFTOOL}"
            "-DBPF_CAPSULE_SKELETON_INPUT=${object}"
            "-DBPF_CAPSULE_SKELETON_OUTPUT=${output}"
            "-DBPF_CAPSULE_SKELETON_NAME=${ARG_NAME}"
            -P "${CMAKE_CURRENT_FUNCTION_LIST_DIR}/GenerateSkeleton.cmake"
        DEPENDS "${object}" ${ARG_DEPENDS}
        COMMENT "libbpf skeleton: ${ARG_NAME}"
        VERBATIM)
    set_source_files_properties("${output}" PROPERTIES GENERATED TRUE)
    add_custom_target(${target} DEPENDS "${output}")
endfunction()
