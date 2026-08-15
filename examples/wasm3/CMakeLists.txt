# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
# WebAssembly in the kernel: stock wasm3 through the same pipeline. Needs a
# pinned source fetched below, or an explicit WASM3_BPF_SOURCE_DIR.
set(WASM3_BPF_SOURCE_DIR
    ""
    CACHE PATH "use an existing wasm3 source tree"
)
if(NOT WASM3_BPF_SOURCE_DIR OR NOT EXISTS "${WASM3_BPF_SOURCE_DIR}/source/m3_core.c")
    fetch_example_source(
        fetched_wasm3
        bpf_capsule_wasm3
        GIT_REPOSITORY
        https://github.com/wasm3/wasm3.git
        GIT_TAG
        6b8bcb1e07bf26ebef09a7211b0a37a446eafd52
        MARKER
        source/m3_core.c
    )
    if(NOT fetched_wasm3)
        message(STATUS "wasm3 example: upstream source unavailable, skipping")
        return()
    endif()
    set(WASM3_BPF_SOURCE_DIR "${fetched_wasm3}")
endif()

# The WASI and tracer back-ends want an operating system; the interpreter
# itself does not.
file(GLOB WASM3_SRC ${WASM3_BPF_SOURCE_DIR}/source/*.c)
list(FILTER WASM3_SRC EXCLUDE REGEX "m3_api_(wasi|uvwasi|meta_wasi|tracer)\\.c$")

set(WASM3_BPF_INCLUDE_DIRECTORIES ${BPF_CAPSULE_LIBC_DIR} ${BPF_CAPSULE_LIBC_DIR}/include
                                  ${WASM3_BPF_SOURCE_DIR}/source
)
set(WASM3_BPF_DEFINITIONS d_m3HasFloat=0 d_m3NoFloatDynamic d_m3FixedHeap=0 d_m3LogOutput=0)
set(WASM3_BPF_OPTIONS # The BPF target intentionally uses wasm3's generic architecture path.
    -Wno-cpp -Wno-implicit-function-declaration
)

# Debug info comes from our own files only: clang crashes emitting it for
# large third-party sources on this target (see the lua target).
bpf_capsule_bitcode(
    WASM3_DRIVER_BC
    DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/zlib_wasm_module.h
    SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/wasm3_bpf.c ${BPF_CAPSULE_LIBC_DIR}/freestanding.c
            ${BPF_CAPSULE_LIBC_DIR}/tlsf.c ${BPF_CAPSULE_LIBC_DIR}/softfloat.c
            ${BPF_CAPSULE_LIBC_DIR}/mathfns.c
    INCLUDE_DIRECTORIES ${WASM3_BPF_INCLUDE_DIRECTORIES}
    COMPILE_DEFINITIONS ${WASM3_BPF_DEFINITIONS}
    COMPILE_OPTIONS ${WASM3_BPF_OPTIONS} -g
)
bpf_capsule_bitcode(
    WASM3_UPSTREAM_BC
    SOURCES ${WASM3_SRC}
    INCLUDE_DIRECTORIES ${WASM3_BPF_INCLUDE_DIRECTORIES}
    COMPILE_DEFINITIONS ${WASM3_BPF_DEFINITIONS}
    COMPILE_OPTIONS ${WASM3_BPF_OPTIONS} -g0
)

bpf_capsule_object(
    wasm3_bpf_lib_output
    OUTPUT wasm3_bpf_lib.o
    BITCODE ${WASM3_DRIVER_BC} ${WASM3_UPSTREAM_BC}
)
bpf_capsule_skeleton(
    wasm3_skeleton
    OUTPUT "${CMAKE_CURRENT_BINARY_DIR}/wasm3.skel.h"
    OBJECT "${CMAKE_CURRENT_BINARY_DIR}/wasm3_bpf_lib.o"
    NAME wasm3
    DEPENDS wasm3_bpf_lib_output
)

# Native reference: the same interpreter, the same module.
add_executable(wasm3 wasm3_host.c ${WASM3_SRC} "${CMAKE_CURRENT_BINARY_DIR}/wasm3.skel.h")
set_source_files_properties(${WASM3_SRC} PROPERTIES COMPILE_OPTIONS -w)
target_include_directories(
    wasm3 PRIVATE "${CMAKE_CURRENT_BINARY_DIR}" ${BPF_CAPSULE_INCLUDE_DIRS}
                  ${WASM3_BPF_SOURCE_DIR}/source
)
target_compile_options(wasm3 PRIVATE -Wall -Wextra -Dd_m3HasFloat=0 -Dd_m3NoFloatDynamic)
find_package(ZLIB REQUIRED)
target_link_libraries(wasm3 PkgConfig::LibBpf ZLIB::ZLIB m)
add_dependencies(wasm3 wasm3_skeleton)

install(TARGETS wasm3 RUNTIME DESTINATION libexec/bpf-capsule/examples/wasm3)
if(BPF_CAPSULE_INSTALL_TEST_ARTIFACTS)
    install(FILES "${CMAKE_CURRENT_BINARY_DIR}/wasm3_bpf_lib.o"
            DESTINATION libexec/bpf-capsule/examples/wasm3
    )
endif()
install(
    FILES "${WASM3_BPF_SOURCE_DIR}/LICENSE"
    DESTINATION share/licenses/bpf-capsule-examples
    RENAME wasm3-LICENSE
)
