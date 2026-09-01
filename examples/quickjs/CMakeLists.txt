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
    set(QUICKJS_BPF_SOURCE_DIR "${fetched_quickjs}")
endif()

set(QUICKJS_PATCH "${CMAKE_CURRENT_SOURCE_DIR}/patches/0001-add-bpf-configuration.patch")
set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS "${QUICKJS_PATCH}")
set(QUICKJS_BUILD_SOURCE_DIR "${CMAKE_CURRENT_BINARY_DIR}/quickjs-source")
file(MAKE_DIRECTORY "${QUICKJS_BUILD_SOURCE_DIR}")
configure_file("${QUICKJS_BPF_SOURCE_DIR}/quickjs.c" "${QUICKJS_BUILD_SOURCE_DIR}/quickjs.c"
               COPYONLY
)
file(
    CHMOD "${QUICKJS_BUILD_SOURCE_DIR}/quickjs.c"
    PERMISSIONS OWNER_READ OWNER_WRITE GROUP_READ WORLD_READ
)
find_program(PATCH_EXECUTABLE patch REQUIRED)
execute_process(
    COMMAND "${PATCH_EXECUTABLE}" --quiet --batch -p1 -i "${QUICKJS_PATCH}"
    WORKING_DIRECTORY "${QUICKJS_BUILD_SOURCE_DIR}"
    RESULT_VARIABLE QUICKJS_PATCH_RESULT
)
if(NOT QUICKJS_PATCH_RESULT EQUAL 0)
    message(FATAL_ERROR "QuickJS example: cannot apply ${QUICKJS_PATCH}")
endif()

set(QUICKJS_SRC
    ${QUICKJS_BUILD_SOURCE_DIR}/quickjs.c ${QUICKJS_BPF_SOURCE_DIR}/cutils.c
    ${QUICKJS_BPF_SOURCE_DIR}/libregexp.c ${QUICKJS_BPF_SOURCE_DIR}/libunicode.c
    ${QUICKJS_BPF_SOURCE_DIR}/dtoa.c
)

set(QUICKJS_BPF_INCLUDE_DIRECTORIES ${BPF_CAPSULE_LIBC_DIR} ${BPF_CAPSULE_LIBC_DIR}/include
                                    ${QUICKJS_BPF_SOURCE_DIR}
)
set(QUICKJS_BPF_DEFINITIONS
    CONFIG_VERSION="bpf"
    # Disable the thread-backed Atomics object and computed-goto dispatch while
    # retaining stack checks and the ordinary allocator accounting path.
    CONFIG_BPF=1
)
# Debug info comes from our integration source, not the large upstream files.
bpf_capsule_bitcode(
    QUICKJS_DRIVER_BC
    SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/quickjs_bpf.c ${BPF_CAPSULE_LIBC_DIR}/freestanding.c
            ${BPF_CAPSULE_LIBC_DIR}/tlsf_capsule.c ${BPF_CAPSULE_LIBC_DIR}/softfloat.c
            ${BPF_CAPSULE_LIBC_DIR}/mathfns.c ${BPF_CAPSULE_LIBC_DIR}/strtod.c
            ${BPF_CAPSULE_LIBC_DIR}/int128.c
    INCLUDE_DIRECTORIES ${QUICKJS_BPF_INCLUDE_DIRECTORIES}
    COMPILE_DEFINITIONS ${QUICKJS_BPF_DEFINITIONS}
    COMPILE_OPTIONS -g
)
bpf_capsule_bitcode(
    QUICKJS_UPSTREAM_BC
    SOURCES ${QUICKJS_SRC}
    INCLUDE_DIRECTORIES ${QUICKJS_BPF_INCLUDE_DIRECTORIES}
    COMPILE_DEFINITIONS ${QUICKJS_BPF_DEFINITIONS}
    COMPILE_OPTIONS -g0
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

add_executable(quickjs quickjs_host.c "${CMAKE_CURRENT_BINARY_DIR}/quickjs.skel.h")
target_include_directories(quickjs PRIVATE "${CMAKE_CURRENT_BINARY_DIR}" ${BPF_CAPSULE_INCLUDE_DIRS})
target_compile_options(quickjs PRIVATE -Wall -Wextra)
target_link_libraries(quickjs PRIVATE ${BPF_CAPSULE_HOST_TARGET})
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
