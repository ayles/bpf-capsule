# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
include(FetchContent)

# TLSF is shared by several installed example objects. Keep its complete BSD
# notice in binary installations as well as beside the source header.
install(
    FILES "${BPF_CAPSULE_TLSF_DIR}/LICENSE"
    DESTINATION share/licenses/bpf-capsule-examples
    RENAME tlsf-LICENSE
)

# Source acquisition is private example infrastructure, not part of the
# installed BPF Capsule compiler API. Upstream projects are fetched but never
# configured: their C sources are inputs to our pipeline.
function(fetch_example_source out_var name)
    cmake_parse_arguments(
        ARG "" "GIT_REPOSITORY;GIT_TAG;URL;URL_HASH;MARKER;ROOT_SUBDIR" "" ${ARGN}
    )
    if(ARG_UNPARSED_ARGUMENTS)
        message(
            FATAL_ERROR
                "fetch_example_source(${out_var}) received unknown arguments: ${ARG_UNPARSED_ARGUMENTS}"
        )
    endif()
    set(fetch_args)
    if(ARG_GIT_REPOSITORY)
        list(
            APPEND
            fetch_args
            GIT_REPOSITORY
            "${ARG_GIT_REPOSITORY}"
            GIT_TAG
            "${ARG_GIT_TAG}"
            GIT_SHALLOW
            FALSE
        )
    elseif(ARG_URL)
        list(
            APPEND
            fetch_args
            URL
            "${ARG_URL}"
            URL_HASH
            "SHA256=${ARG_URL_HASH}"
            DOWNLOAD_EXTRACT_TIMESTAMP
            TRUE
        )
    else()
        message(FATAL_ERROR "${name}: no upstream repository or URL")
    endif()

    FetchContent_Declare(${name} ${fetch_args} SOURCE_SUBDIR .bpf-capsule-do-not-build)
    FetchContent_MakeAvailable(${name})
    FetchContent_GetProperties(${name} SOURCE_DIR source_dir)

    if(ARG_ROOT_SUBDIR AND EXISTS "${source_dir}/${ARG_ROOT_SUBDIR}/${ARG_MARKER}")
        set(source_dir "${source_dir}/${ARG_ROOT_SUBDIR}")
    endif()
    if(NOT EXISTS "${source_dir}/${ARG_MARKER}")
        message(FATAL_ERROR "${name}: fetched source lacks ${ARG_MARKER} at ${source_dir}")
    endif()
    set(${out_var}
        "${source_dir}"
        PARENT_SCOPE
    )
endfunction()

set(BPF_CAPSULE_KNOWN_EXAMPLES
    fib
    zlib
    sqlite
    lua
    lua-xdp
    wasm3
    llama2
    quickjs
    rust
    doom
)

foreach(requested IN LISTS BPF_CAPSULE_EXAMPLES)
    if(NOT requested STREQUAL "all" AND NOT requested IN_LIST BPF_CAPSULE_KNOWN_EXAMPLES)
        message(FATAL_ERROR "Unknown BPF Capsule example: ${requested}")
    endif()
endforeach()

foreach(example IN LISTS BPF_CAPSULE_KNOWN_EXAMPLES)
    if("all" IN_LIST BPF_CAPSULE_EXAMPLES OR example IN_LIST BPF_CAPSULE_EXAMPLES)
        add_subdirectory("${example}")
    endif()
endforeach()
