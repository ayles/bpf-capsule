# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
# JavaScript in the kernel: stock QuickJS through the same pipeline. Needs a
# pinned source fetched below, or an explicit QUICKJS_BPF_SOURCE_DIR.
set(QUICKJS_BPF_SOURCE_DIR
    ""
    CACHE PATH "use an existing QuickJS source tree"
)
if(NOT QUICKJS_BPF_SOURCE_DIR OR NOT EXISTS "${QUICKJS_BPF_SOURCE_DIR}/quickjs.c")
    fetch_example_source(
        fetched_quickjs
        bpf_capsule_quickjs
        GIT_REPOSITORY
        https://github.com/bellard/quickjs.git
        GIT_TAG
        04be246001599f5995fa2f2d8c91a0f198d3f34c
        MARKER
        quickjs.c
    )
    if(NOT fetched_quickjs)
        message(STATUS "QuickJS example: upstream source unavailable, skipping")
        return()
    endif()
    set(QUICKJS_BPF_SOURCE_DIR "${fetched_quickjs}")
endif()

set(QUICKJS_SRC
    ${QUICKJS_BPF_SOURCE_DIR}/quickjs.c ${QUICKJS_BPF_SOURCE_DIR}/cutils.c
    ${QUICKJS_BPF_SOURCE_DIR}/libregexp.c ${QUICKJS_BPF_SOURCE_DIR}/libunicode.c
    ${QUICKJS_BPF_SOURCE_DIR}/dtoa.c
)

set(QUICKJS_BPF_INCLUDE_DIRECTORIES ${BPF_CAPSULE_LIBC_DIR} ${BPF_CAPSULE_LIBC_DIR}/include
                                    ${QUICKJS_BPF_SOURCE_DIR}
)
set(QUICKJS_BPF_DEFINITIONS
    CONFIG_VERSION="bpf"
    # QuickJS gates OS threads, atomics and its stack-limit check on this: a
    # single-threaded machine with no call stack of its own is exactly the
    # configuration it describes.
    __EMSCRIPTEN__=1
    _GNU_SOURCE
)
set(QUICKJS_BPF_OPTIONS
    # Without this QuickJS picks 64-bit bignum limbs and 128-bit arithmetic,
    # which BPF cannot lower (__multi3/__udivti3 libcalls).
    -U__SIZEOF_INT128__ -Wno-implicit-function-declaration -Wno-incompatible-pointer-types
    -Wno-return-type
)
# Debug info only on our own files: clang crashes emitting it for large
# third-party sources on this target (see the lua target).
bpf_capsule_bitcode(
    QUICKJS_DRIVER_BC
    SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/quickjs_bpf.c ${BPF_CAPSULE_LIBC_DIR}/freestanding.c
            ${BPF_CAPSULE_LIBC_DIR}/tlsf.c ${BPF_CAPSULE_LIBC_DIR}/softfloat.c
            ${BPF_CAPSULE_LIBC_DIR}/mathfns.c
    INCLUDE_DIRECTORIES ${QUICKJS_BPF_INCLUDE_DIRECTORIES}
    COMPILE_DEFINITIONS ${QUICKJS_BPF_DEFINITIONS}
    COMPILE_OPTIONS ${QUICKJS_BPF_OPTIONS} -g
)
bpf_capsule_bitcode(
    QUICKJS_UPSTREAM_BC
    SOURCES ${QUICKJS_SRC}
    INCLUDE_DIRECTORIES ${QUICKJS_BPF_INCLUDE_DIRECTORIES}
    COMPILE_DEFINITIONS ${QUICKJS_BPF_DEFINITIONS}
    COMPILE_OPTIONS ${QUICKJS_BPF_OPTIONS} -g0
)

bpf_capsule_object(
    quickjs_bpf_lib_output
    OUTPUT quickjs_bpf_lib.o
    BITCODE ${QUICKJS_DRIVER_BC} ${QUICKJS_UPSTREAM_BC}
)
bpf_capsule_skeleton(
    quickjs_skeleton
    OUTPUT "${CMAKE_CURRENT_BINARY_DIR}/quickjs.skel.h"
    OBJECT "${CMAKE_CURRENT_BINARY_DIR}/quickjs_bpf_lib.o"
    NAME quickjs
    DEPENDS quickjs_bpf_lib_output
)

add_executable(quickjs quickjs_host.c ${QUICKJS_SRC} "${CMAKE_CURRENT_BINARY_DIR}/quickjs.skel.h")
set_source_files_properties(${QUICKJS_SRC} PROPERTIES COMPILE_OPTIONS -w)
target_include_directories(
    quickjs PRIVATE "${CMAKE_CURRENT_BINARY_DIR}" ${BPF_CAPSULE_INCLUDE_DIRS}
                    ${QUICKJS_BPF_SOURCE_DIR}
)
target_compile_options(
    quickjs PRIVATE -Wall -Wextra -Wno-unused-parameter -DCONFIG_VERSION="host" -D_GNU_SOURCE
)
target_link_libraries(quickjs PRIVATE PkgConfig::LibBpf m pthread)
add_dependencies(quickjs quickjs_skeleton)

install(TARGETS quickjs RUNTIME DESTINATION libexec/bpf-capsule/examples/quickjs)
install(FILES "${CMAKE_CURRENT_SOURCE_DIR}/script.js"
        DESTINATION libexec/bpf-capsule/examples/quickjs
)
if(BPF_CAPSULE_INSTALL_TEST_ARTIFACTS)
    install(FILES "${CMAKE_CURRENT_BINARY_DIR}/quickjs_bpf_lib.o"
            DESTINATION libexec/bpf-capsule/examples/quickjs
    )
endif()
install(
    FILES "${QUICKJS_BPF_SOURCE_DIR}/LICENSE"
    DESTINATION share/licenses/bpf-capsule-examples
    RENAME quickjs-LICENSE
)
