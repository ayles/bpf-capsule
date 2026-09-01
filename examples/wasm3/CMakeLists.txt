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
        0cd38327f0c721e75172f4f1eeb55854dc0517af
        MARKER
        source/m3_core.c
    )
    set(WASM3_BPF_SOURCE_DIR "${fetched_wasm3}")
endif()

# The interpreted module uses the same pinned zlib release as the direct zlib
# example, but wasm3 must also remain independently buildable.
set(ZLIB_BPF_SOURCE_DIR
    ""
    CACHE PATH "use an existing zlib source tree"
)
if(NOT ZLIB_BPF_SOURCE_DIR OR NOT EXISTS "${ZLIB_BPF_SOURCE_DIR}/inflate.c")
    fetch_example_source(
        fetched_zlib
        bpf_capsule_zlib
        GIT_REPOSITORY
        https://github.com/madler/zlib.git
        GIT_TAG
        da607da739fa6047df13e66a2af6b8bec7c2a498
        MARKER
        inflate.c
    )
    set(ZLIB_BPF_SOURCE_DIR "${fetched_zlib}")
endif()

# The WASI and tracer back-ends want an operating system; the interpreter
# itself does not.
file(GLOB WASM3_SRC ${WASM3_BPF_SOURCE_DIR}/source/*.c)
list(FILTER WASM3_SRC EXCLUDE REGEX "m3_api_(wasi|uvwasi|meta_wasi|tracer)\\.c$")

set(WASM3_BPF_INCLUDE_DIRECTORIES ${BPF_CAPSULE_LIBC_DIR} ${BPF_CAPSULE_LIBC_DIR}/include
                                  ${WASM3_BPF_SOURCE_DIR}/source
)
# wasm3 bounds recursive interpreter calls against its native stack. Capsule
# must reserve part of each fiber stack for the surrounding C call chain
# instead of inheriting wasm3's desktop-sized 8 MiB default.
math(EXPR WASM3_NATIVE_STACK_BYTES "${BPF_CAPSULE_FIBER_STACK_BYTES} / 2")
set(WASM3_BPF_DEFINITIONS M3_ARCH=\"bpf\"
                          d_m3MaxNativeStack=${WASM3_NATIVE_STACK_BYTES}
)

# Build the module that wasm3 interprets from the same pinned zlib sources as
# the direct zlib example. Keeping the byte array out of the source tree makes
# a dependency update impossible to apply to one copy but not the other.
set(WASM_ZLIB_SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/guest_zlib.c
    ${ZLIB_BPF_SOURCE_DIR}/inflate.c
    ${ZLIB_BPF_SOURCE_DIR}/inftrees.c
    ${ZLIB_BPF_SOURCE_DIR}/inffast.c
    ${ZLIB_BPF_SOURCE_DIR}/adler32.c
    ${ZLIB_BPF_SOURCE_DIR}/crc32.c
    ${ZLIB_BPF_SOURCE_DIR}/zutil.c
)
set(WASM_ZLIB_MODULE "${CMAKE_CURRENT_BINARY_DIR}/zlib_guest.wasm")
set(WASM_ZLIB_HEADER "${CMAKE_CURRENT_BINARY_DIR}/zlib_wasm_module.h")
add_custom_command(
    OUTPUT "${WASM_ZLIB_MODULE}"
    COMMAND
        "${BPF_CAPSULE_CLANG}" --target=wasm32 -fuse-ld=lld -O2 -nostdlib
        -DZ_SOLO -I${CMAKE_CURRENT_SOURCE_DIR} -I${BPF_CAPSULE_RUNTIME_DIR}
        -I${ZLIB_BPF_SOURCE_DIR} -Wl,--no-entry -Wl,--export=guest_zlib_run
        -Wl,--export=guest_zin -Wl,--export=guest_zout -Wl,--export=guest_zctrl
        ${WASM_ZLIB_SOURCES} -o "${WASM_ZLIB_MODULE}"
    DEPENDS ${WASM_ZLIB_SOURCES} ${CMAKE_CURRENT_SOURCE_DIR}/wasm3_ctrl.h
    VERBATIM
    COMMAND_EXPAND_LISTS
)
add_custom_command(
    OUTPUT "${WASM_ZLIB_HEADER}"
    COMMAND
        "${CMAKE_COMMAND}" -DINPUT=${WASM_ZLIB_MODULE} -DOUTPUT=${WASM_ZLIB_HEADER}
        -P "${CMAKE_CURRENT_SOURCE_DIR}/GenerateModuleHeader.cmake"
    DEPENDS "${WASM_ZLIB_MODULE}" ${CMAKE_CURRENT_SOURCE_DIR}/GenerateModuleHeader.cmake
    VERBATIM
)

# Debug info comes from our integration sources, not the large upstream files.
bpf_capsule_bitcode(
    WASM3_DRIVER_BC
    DEPENDS "${WASM_ZLIB_HEADER}"
    SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/wasm3_bpf.c ${BPF_CAPSULE_LIBC_DIR}/freestanding.c
            ${BPF_CAPSULE_LIBC_DIR}/tlsf_capsule.c ${BPF_CAPSULE_LIBC_DIR}/softfloat.c
            ${BPF_CAPSULE_LIBC_DIR}/mathfns.c ${BPF_CAPSULE_LIBC_DIR}/strtod.c
    INCLUDE_DIRECTORIES ${CMAKE_CURRENT_BINARY_DIR} ${WASM3_BPF_INCLUDE_DIRECTORIES}
    COMPILE_DEFINITIONS ${WASM3_BPF_DEFINITIONS}
    COMPILE_OPTIONS -g
)
bpf_capsule_bitcode(
    WASM3_UPSTREAM_BC
    SOURCES ${WASM3_SRC}
    INCLUDE_DIRECTORIES ${WASM3_BPF_INCLUDE_DIRECTORIES}
    COMPILE_DEFINITIONS ${WASM3_BPF_DEFINITIONS}
    COMPILE_OPTIONS -g0
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

add_executable(wasm3 wasm3_host.c "${CMAKE_CURRENT_BINARY_DIR}/wasm3.skel.h")
target_include_directories(wasm3 PRIVATE "${CMAKE_CURRENT_BINARY_DIR}" ${BPF_CAPSULE_INCLUDE_DIRS})
target_compile_options(wasm3 PRIVATE -Wall -Wextra)
find_package(ZLIB REQUIRED)
target_link_libraries(wasm3 ${BPF_CAPSULE_HOST_TARGET} ZLIB::ZLIB)
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
install(
    FILES "${ZLIB_BPF_SOURCE_DIR}/LICENSE"
    DESTINATION share/licenses/bpf-capsule-examples
    RENAME wasm3-zlib-LICENSE
)
