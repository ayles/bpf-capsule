# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
# Public CMake integration for the bpf-capsule-cc / bpf-capsule-ld toolchain.
include_guard(GLOBAL)

set(BPF_CAPSULE_MAX_FIBERS "" CACHE STRING "Compiled fiber ceiling; empty uses the runtime default")
if(
    BPF_CAPSULE_MAX_FIBERS
    AND (NOT BPF_CAPSULE_MAX_FIBERS MATCHES "^[1-9][0-9]*$" OR BPF_CAPSULE_MAX_FIBERS GREATER 65535)
)
    message(
        FATAL_ERROR
        "BPF_CAPSULE_MAX_FIBERS must be an integer from 1 to 65535 or empty, got ${BPF_CAPSULE_MAX_FIBERS}"
    )
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

if(NOT BPF_CAPSULE_RUNTIME_DIR)
    get_filename_component(BPF_CAPSULE_RUNTIME_DIR "${CMAKE_CURRENT_LIST_DIR}/../src/runtime/guest" ABSOLUTE)
endif()
if(NOT BPF_CAPSULE_COMPILER_RUNTIME_DIR)
    get_filename_component(
        BPF_CAPSULE_COMPILER_RUNTIME_DIR
        "${CMAKE_CURRENT_LIST_DIR}/../src/runtime/compiler"
        ABSOLUTE
    )
endif()
if(NOT BPF_CAPSULE_PLATFORM_DIR)
    get_filename_component(BPF_CAPSULE_PLATFORM_DIR "${CMAKE_CURRENT_LIST_DIR}/../src/runtime/platform" ABSOLUTE)
endif()
if(NOT BPF_CAPSULE_LIBC_ARCHIVE)
    message(FATAL_ERROR "BPF Capsule C library archive is unavailable")
endif()
if(NOT BPF_CAPSULE_RUST_RUNTIME_DIR)
    get_filename_component(BPF_CAPSULE_RUST_RUNTIME_DIR "${CMAKE_CURRENT_LIST_DIR}/../src/rust/bpf-capsule-rt" ABSOLUTE)
endif()

# Compile C or C++ translation units into unoptimized BPF-target LLVM bitcode.
# The whole-program optimizer lives in bpf-capsule-ld, so consumers must not
# insert an independent opt/llc stage between these helpers.
function(_bpf_capsule_compile_bitcode out_var)
    cmake_parse_arguments(ARG "" "" "SOURCES;DEPENDS;INCLUDE_DIRECTORIES;COMPILE_DEFINITIONS;COMPILE_OPTIONS" ${ARGN})
    if(ARG_UNPARSED_ARGUMENTS)
        message(
            FATAL_ERROR
            "_bpf_capsule_compile_bitcode(${out_var}) received unknown arguments: ${ARG_UNPARSED_ARGUMENTS}"
        )
    endif()
    if(NOT ARG_SOURCES)
        message(FATAL_ERROR "_bpf_capsule_compile_bitcode(${out_var}) needs SOURCES")
    endif()
    if(NOT BPF_CAPSULE_LIBBPF_TARGET OR NOT TARGET ${BPF_CAPSULE_LIBBPF_TARGET})
        message(FATAL_ERROR "Set BPF_CAPSULE_LIBBPF_TARGET to the imported target that supplies libbpf headers")
    endif()
    set(common_flags ${ARG_COMPILE_OPTIONS})
    foreach(directory IN LISTS ARG_INCLUDE_DIRECTORIES)
        list(APPEND common_flags "$<$<BOOL:${directory}>:-I$<JOIN:${directory},$<SEMICOLON>-I>>")
    endforeach()
    get_target_property(_bpf_capsule_libbpf_includes ${BPF_CAPSULE_LIBBPF_TARGET} INTERFACE_INCLUDE_DIRECTORIES)
    if(_bpf_capsule_libbpf_includes AND NOT _bpf_capsule_libbpf_includes MATCHES "-NOTFOUND$")
        foreach(directory IN LISTS _bpf_capsule_libbpf_includes)
            if(NOT directory MATCHES "^\\$<")
                list(APPEND common_flags "-isystem${directory}")
            endif()
        endforeach()
    endif()
    foreach(definition IN LISTS ARG_COMPILE_DEFINITIONS)
        if(definition MATCHES "^-D")
            list(APPEND common_flags "${definition}")
        else()
            list(APPEND common_flags "$<$<BOOL:${definition}>:-D$<JOIN:${definition},$<SEMICOLON>-D>>")
        endif()
    endforeach()
    if(BPF_CAPSULE_MAX_FIBERS)
        list(APPEND common_flags "-DBPF_CAPSULE_MAX_FIBERS=${BPF_CAPSULE_MAX_FIBERS}")
    endif()

    set(outputs)
    foreach(source IN LISTS ARG_SOURCES)
        cmake_path(
            ABSOLUTE_PATH source
            BASE_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
            NORMALIZE
            OUTPUT_VARIABLE absolute_source
        )
        get_source_file_property(language "${source}" LANGUAGE)
        if(NOT language OR language STREQUAL "NOTFOUND")
            get_filename_component(extension "${source}" LAST_EXT)
            string(REGEX REPLACE "^\\." "" extension "${extension}")
            if(extension IN_LIST CMAKE_CXX_SOURCE_FILE_EXTENSIONS)
                set(language CXX)
            elseif(extension IN_LIST CMAKE_C_SOURCE_FILE_EXTENSIONS)
                set(language C)
            else()
                message(FATAL_ERROR "_bpf_capsule_compile_bitcode: cannot infer language for ${source}")
            endif()
        endif()
        if(NOT language STREQUAL "C" AND NOT language STREQUAL "CXX")
            message(FATAL_ERROR "_bpf_capsule_compile_bitcode: ${source} uses unsupported language ${language}")
        endif()

        set(source_flags ${common_flags})
        if(language STREQUAL "CXX")
            list(APPEND source_flags -fno-exceptions -fno-rtti)
        endif()
        get_filename_component(name "${source}" NAME_WE)
        string(MD5 source_id "${absolute_source};${language};${source_flags}")
        string(SUBSTRING "${source_id}" 0 8 source_id)
        set(bitcode "${CMAKE_CURRENT_BINARY_DIR}/bc/${name}-${source_id}.bc")
        add_custom_command(
            OUTPUT "${bitcode}"
            COMMAND ${CMAKE_COMMAND} -E make_directory "${CMAKE_CURRENT_BINARY_DIR}/bc"
            COMMAND
                $<TARGET_FILE:${BPF_CAPSULE_CC_TARGET}> ${source_flags} -MD -MF "${bitcode}.d" -MT "${bitcode}" -c
                "${absolute_source}" -o "${bitcode}"
            DEPENDS ${BPF_CAPSULE_CC_TARGET} "${absolute_source}" ${ARG_DEPENDS}
            DEPFILE "${bitcode}.d"
            COMMENT "capsule-cc: ${name}"
            COMMAND_EXPAND_LISTS
            VERBATIM
        )
        list(APPEND outputs "${bitcode}")
    endforeach()
    set(${out_var} ${outputs} PARENT_SCOPE)
endfunction()

function(_bpf_capsule_find_llvm_tool variable name)
    find_program(
        ${variable}
        NAMES ${name}-${BPF_CAPSULE_LLVM_MAJOR} ${name}
        HINTS "${BPF_CAPSULE_LLVM_TOOLS_DIR}" "${LLVM_TOOLS_BINARY_DIR}"
        REQUIRED
    )
    execute_process(
        COMMAND "${${variable}}" --version
        RESULT_VARIABLE result
        OUTPUT_VARIABLE version
        ERROR_VARIABLE error
        OUTPUT_STRIP_TRAILING_WHITESPACE
    )
    string(REGEX MATCH "LLVM version ([0-9]+)" _ "${version}")
    if(NOT result EQUAL 0 OR NOT CMAKE_MATCH_1 STREQUAL BPF_CAPSULE_LLVM_MAJOR)
        message(
            FATAL_ERROR
            "${variable} must be LLVM ${BPF_CAPSULE_LLVM_MAJOR}; got ${${variable}}: ${version}${error}"
        )
    endif()
endfunction()

# Resolve archive targets without changing CMake's host compiler or archiver.
# Imported STATIC libraries and ordinary INTERFACE header libraries work too.
function(_bpf_capsule_library_inputs out_var)
    set(archives)
    set(includes)
    set(definitions)
    set(options)
    set(pending ${ARGN})
    set(visited)
    # CMake resolves transitive usage requirements, including PRIVATE and
    # LINK_ONLY, from the explicitly linked targets. Walk dependencies below
    # only to collect archives, not to re-export their private compile flags.
    foreach(library IN LISTS ARGN)
        list(APPEND includes "$<TARGET_PROPERTY:${library},INTERFACE_INCLUDE_DIRECTORIES>")
        list(APPEND definitions "$<TARGET_PROPERTY:${library},INTERFACE_COMPILE_DEFINITIONS>")
        list(APPEND options "$<TARGET_PROPERTY:${library},INTERFACE_COMPILE_OPTIONS>")
    endforeach()
    while(pending)
        list(POP_FRONT pending library)
        if(library IN_LIST visited)
            continue()
        endif()
        list(APPEND visited "${library}")
        if(NOT TARGET "${library}")
            message(FATAL_ERROR "Capsule library target does not exist: ${library}")
        endif()
        get_target_property(archive "${library}" BPF_CAPSULE_ARCHIVE)
        get_target_property(type "${library}" TYPE)
        if(archive)
            list(APPEND archives "${archive}")
        elseif(type STREQUAL "STATIC_LIBRARY")
            list(APPEND archives "$<TARGET_FILE:${library}>")
        elseif(NOT type STREQUAL "INTERFACE_LIBRARY")
            message(FATAL_ERROR "Capsule library ${library} must be a static bitcode or interface library")
        endif()
        get_target_property(dependencies "${library}" INTERFACE_LINK_LIBRARIES)
        if(dependencies)
            foreach(dependency IN LISTS dependencies)
                if(dependency MATCHES "^\\$<LINK_ONLY:(.+)>$")
                    set(dependency "${CMAKE_MATCH_1}")
                endif()
                if(IS_ABSOLUTE "${dependency}")
                    list(APPEND archives "${dependency}")
                else()
                    list(APPEND pending "${dependency}")
                endif()
            endforeach()
        endif()
    endwhile()
    list(REMOVE_DUPLICATES archives)
    set(${out_var} "${archives}" PARENT_SCOPE)
    set(${out_var}_includes "${includes}" PARENT_SCOPE)
    set(${out_var}_definitions "${definitions}" PARENT_SCOPE)
    set(${out_var}_options "${options}" PARENT_SCOPE)
endfunction()

# A reusable bitcode archive: no runtime, kernel profile, or whole-program
# optimization. Ordinary target_* commands control its build and interface.
function(bpf_capsule_library target)
    cmake_parse_arguments(ARG "" "OUTPUT" "SOURCES;BITCODE;DEPENDS" ${ARGN})
    if(ARG_UNPARSED_ARGUMENTS)
        message(FATAL_ERROR "bpf_capsule_library(${target}) received unknown arguments: ${ARG_UNPARSED_ARGUMENTS}")
    endif()
    if(NOT ARG_SOURCES AND NOT ARG_BITCODE)
        message(FATAL_ERROR "bpf_capsule_library(${target}) needs SOURCES or BITCODE")
    endif()
    if(NOT ARG_OUTPUT)
        set(ARG_OUTPUT "lib${target}.a")
    endif()
    cmake_path(ABSOLUTE_PATH ARG_OUTPUT BASE_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}" NORMALIZE OUTPUT_VARIABLE archive)
    get_filename_component(archive_directory "${archive}" DIRECTORY)
    _bpf_capsule_find_llvm_tool(BPF_CAPSULE_LLVM_AR llvm-ar)
    # An OBJECT target provides normal PRIVATE/PUBLIC/INTERFACE properties
    # without invoking the host archiver. Its only output is built below.
    add_library(${target} OBJECT)
    set_target_properties(${target} PROPERTIES LINKER_LANGUAGE C BPF_CAPSULE_ARCHIVE "${archive}")
    set(bitcode ${ARG_BITCODE})
    if(ARG_SOURCES)
        _bpf_capsule_compile_bitcode(
            compiled_bitcode
            SOURCES ${ARG_SOURCES}
            DEPENDS ${ARG_DEPENDS}
            INCLUDE_DIRECTORIES "$<TARGET_PROPERTY:${target},INCLUDE_DIRECTORIES>"
            COMPILE_DEFINITIONS "$<TARGET_PROPERTY:${target},COMPILE_DEFINITIONS>"
            COMPILE_OPTIONS "$<TARGET_PROPERTY:${target},COMPILE_OPTIONS>"
        )
        list(APPEND bitcode ${compiled_bitcode})
    endif()
    add_custom_command(
        OUTPUT "${archive}"
        COMMAND "${CMAKE_COMMAND}" -E make_directory "${archive_directory}"
        # A fresh archive also removes members whose sources were removed.
        COMMAND "${CMAKE_COMMAND}" -E rm -f "${archive}.tmp"
        COMMAND "${BPF_CAPSULE_LLVM_AR}" rcsD "${archive}.tmp" ${bitcode}
        COMMAND "${CMAKE_COMMAND}" -E rename "${archive}.tmp" "${archive}"
        DEPENDS ${bitcode} ${ARG_DEPENDS} "${BPF_CAPSULE_LLVM_AR}"
        COMMENT "capsule archive: ${target}"
        COMMAND_EXPAND_LISTS
        VERBATIM
    )
    set_source_files_properties("${archive}" PROPERTIES HEADER_FILE_ONLY TRUE)
    target_sources(${target} PRIVATE "${archive}")
endfunction()

# Rust remains a Cargo language frontend. This helper turns Cargo's staticlib
# into one ordinary LLVM bitcode input; bpf-capsule-ld still owns every
# whole-program transform and all BPF code generation.
function(bpf_capsule_rust_bitcode out_var)
    cmake_parse_arguments(ARG "LOCKED;NO_DEFAULT_FEATURES" "MANIFEST_PATH;PACKAGE" "FEATURES;DEPENDS;RUSTFLAGS" ${ARGN})
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
    if(NOT BPF_CAPSULE_LLVM_MAJOR)
        message(FATAL_ERROR "BPF Capsule package did not declare its LLVM major")
    endif()

    find_program(BPF_CAPSULE_CARGO NAMES cargo REQUIRED)
    _bpf_capsule_find_llvm_tool(BPF_CAPSULE_LLVM_AR llvm-ar)
    _bpf_capsule_find_llvm_tool(BPF_CAPSULE_LLVM_LINK llvm-link)

    set(cargo_features ${ARG_FEATURES})
    list(SORT cargo_features)
    string(REPLACE ";" "," cargo_features_argument "${cargo_features}")
    set(metadata_arguments
        --config
        "patch.crates-io.bpf-capsule-rt.path=\"${BPF_CAPSULE_RUST_RUNTIME_DIR}\""
        metadata
        --format-version=1
        --manifest-path
        "${manifest}"
    )
    if(cargo_features)
        list(APPEND metadata_arguments --features "${cargo_features_argument}")
    endif()
    if(ARG_LOCKED)
        list(APPEND metadata_arguments --locked)
    endif()
    if(ARG_NO_DEFAULT_FEATURES)
        list(APPEND metadata_arguments --no-default-features)
    endif()
    execute_process(
        COMMAND "${BPF_CAPSULE_CARGO}" ${metadata_arguments}
        RESULT_VARIABLE metadata_result
        OUTPUT_VARIABLE metadata
        ERROR_VARIABLE metadata_error
        OUTPUT_STRIP_TRAILING_WHITESPACE
    )
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
            file(
                GLOB_RECURSE package_inputs
                CONFIGURE_DEPENDS
                "${package_directory}/*.rs"
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
            "${CMAKE_COMMAND}" "-DBPF_CAPSULE_CARGO=${BPF_CAPSULE_CARGO}" "-DBPF_CAPSULE_LLVM_AR=${BPF_CAPSULE_LLVM_AR}"
            "-DBPF_CAPSULE_LLVM_LINK=${BPF_CAPSULE_LLVM_LINK}"
            "-DBPF_CAPSULE_RUST_RUNTIME_DIR=${BPF_CAPSULE_RUST_RUNTIME_DIR}" "-DBPF_CAPSULE_CARGO_MANIFEST=${manifest}"
            "-DBPF_CAPSULE_CARGO_PACKAGE=${ARG_PACKAGE}" "-DBPF_CAPSULE_CARGO_FEATURES=${cargo_features_argument}"
            "-DBPF_CAPSULE_CARGO_LOCKED=${ARG_LOCKED}"
            "-DBPF_CAPSULE_CARGO_NO_DEFAULT_FEATURES=${ARG_NO_DEFAULT_FEATURES}"
            "-DBPF_CAPSULE_CARGO_TARGET_DIR=${cargo_target_directory}" "-DBPF_CAPSULE_RUSTFLAGS=${rustflags}"
            "-DBPF_CAPSULE_RUST_OUTPUT=${cargo_bitcode}" -P "${CMAKE_CURRENT_FUNCTION_LIST_DIR}/BuildRustBitcode.cmake"
        DEPENDS ${cargo_inputs} ${ARG_DEPENDS}
        COMMENT "Cargo bitcode: ${ARG_PACKAGE}"
        VERBATIM
    )

    set(${out_var} "${cargo_bitcode}" PARENT_SCOPE)
endfunction()

# Compile the Capsule-specific platform beneath Picolibc once per consumer
# directory and allocator-lock shape. Picolibc itself remains a normal static
# bitcode archive and is linked separately below.
function(_bpf_capsule_platform_bitcode out_var)
    cmake_parse_arguments(ARG "" "" "COMPILE_DEFINITIONS" ${ARGN})
    if(ARG_UNPARSED_ARGUMENTS)
        message(
            FATAL_ERROR
            "_bpf_capsule_platform_bitcode(${out_var}) received unknown arguments: ${ARG_UNPARSED_ARGUMENTS}"
        )
    endif()
    string(MD5 platform_key "${ARG_COMPILE_DEFINITIONS}")
    get_property(platform_bitcode DIRECTORY PROPERTY "BPF_CAPSULE_PLATFORM_BITCODE_${platform_key}")
    get_property(platform_target DIRECTORY PROPERTY "BPF_CAPSULE_PLATFORM_TARGET_${platform_key}")
    if(NOT platform_bitcode)
        if(NOT IS_DIRECTORY "${BPF_CAPSULE_PLATFORM_DIR}")
            message(FATAL_ERROR "BPF Capsule platform sources are unavailable: ${BPF_CAPSULE_PLATFORM_DIR}")
        endif()
        if(NOT IS_DIRECTORY "${BPF_CAPSULE_TLSF_DIR}")
            message(FATAL_ERROR "BPF Capsule TLSF sources are unavailable: ${BPF_CAPSULE_TLSF_DIR}")
        endif()
        _bpf_capsule_compile_bitcode(
            platform_bitcode
            SOURCES
                "${BPF_CAPSULE_PLATFORM_DIR}/allocator.c"
                "${BPF_CAPSULE_PLATFORM_DIR}/picolibc.c"
                "${BPF_CAPSULE_PLATFORM_DIR}/syscalls.c"
                "${BPF_CAPSULE_PLATFORM_DIR}/tlsf_capsule.c"
            INCLUDE_DIRECTORIES "${BPF_CAPSULE_TLSF_DIR}"
            COMPILE_DEFINITIONS ${ARG_COMPILE_DEFINITIONS}
            COMPILE_OPTIONS -g
        )
        string(MD5 target_id "${CMAKE_CURRENT_BINARY_DIR};platform;${platform_key}")
        set(platform_target "bpf_capsule_platform_${target_id}")
        add_custom_target(${platform_target} DEPENDS ${platform_bitcode})
        set_property(DIRECTORY PROPERTY "BPF_CAPSULE_PLATFORM_BITCODE_${platform_key}" "${platform_bitcode}")
        set_property(DIRECTORY PROPERTY "BPF_CAPSULE_PLATFORM_TARGET_${platform_key}" "${platform_target}")
    endif()
    set(${out_var} "${platform_bitcode}" PARENT_SCOPE)
    set(${out_var}_target "${platform_target}" PARENT_SCOPE)
endfunction()

# Compile the object runtime once per directory and geometry definition set.
function(_bpf_capsule_runtime_bitcode out_var)
    cmake_parse_arguments(ARG "" "" "COMPILE_DEFINITIONS" ${ARGN})
    if(ARG_UNPARSED_ARGUMENTS)
        message(
            FATAL_ERROR
            "_bpf_capsule_runtime_bitcode(${out_var}) received unknown arguments: ${ARG_UNPARSED_ARGUMENTS}"
        )
    endif()
    string(MD5 runtime_key "${ARG_COMPILE_DEFINITIONS}")
    get_property(runtime_bitcode DIRECTORY PROPERTY "BPF_CAPSULE_RUNTIME_BITCODE_${runtime_key}")
    get_property(runtime_target DIRECTORY PROPERTY "BPF_CAPSULE_RUNTIME_TARGET_${runtime_key}")
    if(NOT runtime_bitcode)
        set(runtime_source "${BPF_CAPSULE_RUNTIME_DIR}/bpf_capsule.c")
        if(NOT EXISTS "${runtime_source}")
            message(FATAL_ERROR "BPF Capsule runtime source is unavailable: ${runtime_source}")
        endif()
        _bpf_capsule_compile_bitcode(
            runtime_bitcode
            SOURCES "${runtime_source}"
            COMPILE_DEFINITIONS ${ARG_COMPILE_DEFINITIONS}
            COMPILE_OPTIONS -g
        )
        string(MD5 target_id "${CMAKE_CURRENT_BINARY_DIR};runtime;${runtime_key}")
        set(runtime_target "bpf_capsule_runtime_${target_id}")
        add_custom_target(${runtime_target} DEPENDS ${runtime_bitcode})
        set_property(DIRECTORY PROPERTY "BPF_CAPSULE_RUNTIME_BITCODE_${runtime_key}" "${runtime_bitcode}")
        set_property(DIRECTORY PROPERTY "BPF_CAPSULE_RUNTIME_TARGET_${runtime_key}" "${runtime_target}")
    endif()
    set(${out_var} "${runtime_bitcode}" PARENT_SCOPE)
    set(${out_var}_target "${runtime_target}" PARENT_SCOPE)
endfunction()

# Build a complete Capsule object and return its absolute path in out_var. The
# runtime is always included here; a consumer provides only its own sources or
# frontend-produced bitcode.
function(bpf_capsule_object out_var)
    cmake_parse_arguments(
        ARG
        ""
        "OUTPUT"
        "SOURCES;BITCODE;LIBRARIES;DEPENDS;INCLUDE_DIRECTORIES;COMPILE_DEFINITIONS;COMPILE_OPTIONS;SYSTEM_COMPILE_DEFINITIONS;LINK_OPTIONS"
        ${ARGN}
    )
    if(ARG_UNPARSED_ARGUMENTS)
        message(FATAL_ERROR "bpf_capsule_object(${out_var}) received unknown arguments: ${ARG_UNPARSED_ARGUMENTS}")
    endif()
    if(NOT ARG_OUTPUT OR (NOT ARG_SOURCES AND NOT ARG_BITCODE AND NOT ARG_LIBRARIES))
        message(FATAL_ERROR "bpf_capsule_object(${out_var}) needs OUTPUT and SOURCES, BITCODE, or LIBRARIES")
    endif()
    cmake_path(ABSOLUTE_PATH ARG_OUTPUT BASE_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}" NORMALIZE OUTPUT_VARIABLE output)
    get_filename_component(output_directory "${output}" DIRECTORY)
    set(input_bitcode ${ARG_BITCODE})
    _bpf_capsule_library_inputs(libraries ${ARG_LIBRARIES})
    if(ARG_SOURCES)
        _bpf_capsule_compile_bitcode(
            compiled_bitcode
            SOURCES ${ARG_SOURCES}
            DEPENDS ${ARG_DEPENDS} ${ARG_LIBRARIES}
            INCLUDE_DIRECTORIES ${ARG_INCLUDE_DIRECTORIES} ${libraries_includes}
            COMPILE_DEFINITIONS ${ARG_COMPILE_DEFINITIONS} ${libraries_definitions}
            COMPILE_OPTIONS ${ARG_COMPILE_OPTIONS} ${libraries_options}
        )
        list(APPEND input_bitcode ${compiled_bitcode})
    endif()

    # The linker owns target selection. Compile only its private runtime and
    # platform inputs in the matching shape; application translation units
    # remain profile-neutral LLVM bitcode and receive their final target-cpu in ld.
    set(runtime_definitions ${ARG_SYSTEM_COMPILE_DEFINITIONS})
    set(platform_definitions ${ARG_SYSTEM_COMPILE_DEFINITIONS})
    set(memory_backend fixed)
    set(allocator_lock map)
    set(expect_memory_value OFF)
    set(expect_allocator_value OFF)
    foreach(option IN LISTS ARG_LINK_OPTIONS)
        if(expect_memory_value)
            set(memory_backend "${option}")
            set(expect_memory_value OFF)
        elseif(expect_allocator_value)
            set(allocator_lock "${option}")
            set(expect_allocator_value OFF)
        elseif(option MATCHES "^--?memory=(.+)$")
            set(memory_backend "${CMAKE_MATCH_1}")
        elseif(option STREQUAL "--memory" OR option STREQUAL "-memory")
            set(expect_memory_value ON)
        elseif(option MATCHES "^--?allocator-lock=(.+)$")
            set(allocator_lock "${CMAKE_MATCH_1}")
        elseif(option STREQUAL "--allocator-lock" OR option STREQUAL "-allocator-lock")
            set(expect_allocator_value ON)
        endif()
    endforeach()
    if(expect_memory_value OR expect_allocator_value)
        message(FATAL_ERROR "A Capsule linker option is missing its value")
    endif()
    if(memory_backend STREQUAL "arena")
        list(APPEND runtime_definitions BPF_CAPSULE_FEATURE_ARENA=1)
    endif()
    if(allocator_lock STREQUAL "atomic")
        list(APPEND platform_definitions BPF_CAPSULE_FEATURE_FULL_ATOMICS=1)
    endif()
    list(REMOVE_DUPLICATES runtime_definitions)
    list(REMOVE_DUPLICATES platform_definitions)

    _bpf_capsule_runtime_bitcode(runtime_bitcode COMPILE_DEFINITIONS ${runtime_definitions})
    _bpf_capsule_platform_bitcode(platform_bitcode COMPILE_DEFINITIONS ${platform_definitions})
    add_custom_command(
        OUTPUT "${output}"
        COMMAND ${CMAKE_COMMAND} -E make_directory "${output_directory}"
        COMMAND
            $<TARGET_FILE:${BPF_CAPSULE_LD_TARGET}> ${ARG_LINK_OPTIONS} -o "${output}" ${input_bitcode}
            ${runtime_bitcode} ${platform_bitcode} ${libraries} "${BPF_CAPSULE_COMPILER_RUNTIME_ARCHIVE}"
            "${BPF_CAPSULE_LIBC_ARCHIVE}"
        DEPENDS
            ${BPF_CAPSULE_LD_TARGET}
            ${input_bitcode}
            ${runtime_bitcode}
            ${runtime_bitcode_target}
            "${BPF_CAPSULE_COMPILER_RUNTIME_ARCHIVE}"
            ${platform_bitcode}
            ${platform_bitcode_target}
            "${BPF_CAPSULE_LIBC_ARCHIVE}"
            ${BPF_CAPSULE_LIBC_TARGET}
            ${ARG_DEPENDS}
            ${ARG_LIBRARIES}
            ${libraries}
        COMMENT "capsule-ld: ${out_var}"
        COMMAND_EXPAND_LISTS
        VERBATIM
    )
    set(${out_var} "${output}" PARENT_SCOPE)
endfunction()

function(bpf_capsule_skeleton target)
    cmake_parse_arguments(ARG "" "OUTPUT;OBJECT;NAME" "" ${ARGN})
    if(ARG_UNPARSED_ARGUMENTS)
        message(FATAL_ERROR "bpf_capsule_skeleton(${target}) received unknown arguments: ${ARG_UNPARSED_ARGUMENTS}")
    endif()
    if(NOT ARG_OUTPUT OR NOT ARG_OBJECT OR NOT ARG_NAME)
        message(FATAL_ERROR "bpf_capsule_skeleton(${target}) needs OUTPUT, OBJECT, and NAME")
    endif()
    cmake_path(ABSOLUTE_PATH ARG_OBJECT BASE_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}" NORMALIZE OUTPUT_VARIABLE object)
    find_program(BPF_CAPSULE_BPFTOOL NAMES bpftool REQUIRED)
    cmake_path(ABSOLUTE_PATH ARG_OUTPUT BASE_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}" NORMALIZE OUTPUT_VARIABLE output)
    add_custom_command(
        OUTPUT "${output}"
        COMMAND
            "${CMAKE_COMMAND}" "-DBPF_CAPSULE_BPFTOOL=${BPF_CAPSULE_BPFTOOL}" "-DBPF_CAPSULE_SKELETON_INPUT=${object}"
            "-DBPF_CAPSULE_SKELETON_OUTPUT=${output}" "-DBPF_CAPSULE_SKELETON_NAME=${ARG_NAME}" -P
            "${CMAKE_CURRENT_FUNCTION_LIST_DIR}/GenerateSkeleton.cmake"
        DEPENDS "${object}" "${CMAKE_CURRENT_FUNCTION_LIST_DIR}/GenerateSkeleton.cmake"
        COMMENT "libbpf skeleton: ${ARG_NAME}"
        VERBATIM
    )
    get_filename_component(include_directory "${output}" DIRECTORY)
    add_custom_target(${target}_generate DEPENDS "${output}")
    add_library(${target} INTERFACE)
    target_include_directories(${target} INTERFACE "${include_directory}")
    add_dependencies(${target} ${target}_generate)
endfunction()
