# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
# In-kernel zlib: stock zlib sources (inflate side) through the standard
# pipeline. A caller can override the pinned fetch with ZLIB_BPF_SOURCE_DIR.
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

set(ZLIB_SRC
    ${ZLIB_BPF_SOURCE_DIR}/inflate.c ${ZLIB_BPF_SOURCE_DIR}/inftrees.c
    ${ZLIB_BPF_SOURCE_DIR}/inffast.c ${ZLIB_BPF_SOURCE_DIR}/adler32.c
    ${ZLIB_BPF_SOURCE_DIR}/crc32.c ${ZLIB_BPF_SOURCE_DIR}/zutil.c
)

bpf_capsule_bitcode(
    ZLIB_BC
    SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/zlib_bpf.c ${ZLIB_SRC}
    INCLUDE_DIRECTORIES ${BPF_CAPSULE_LIBC_DIR}/include ${ZLIB_BPF_SOURCE_DIR}
    COMPILE_DEFINITIONS Z_SOLO
    COMPILE_OPTIONS -g
)

bpf_capsule_object(
    zlib_bpf_lib_output
    OUTPUT zlib_bpf_lib.o
    BITCODE ${ZLIB_BC}
)
bpf_capsule_skeleton(
    zlib_skeleton
    OUTPUT "${CMAKE_CURRENT_BINARY_DIR}/zlib.skel.h"
    OBJECT "${CMAKE_CURRENT_BINARY_DIR}/zlib_bpf_lib.o"
    NAME zlib
    DEPENDS zlib_bpf_lib_output
)

find_package(ZLIB REQUIRED)

add_executable(zlib zlib_host.c "${CMAKE_CURRENT_BINARY_DIR}/zlib.skel.h")
target_include_directories(zlib PRIVATE "${CMAKE_CURRENT_BINARY_DIR}" ${BPF_CAPSULE_INCLUDE_DIRS})
target_compile_options(zlib PRIVATE -Wall -Wextra)
target_link_libraries(zlib PRIVATE ${BPF_CAPSULE_HOST_TARGET} ZLIB::ZLIB)
add_dependencies(zlib zlib_skeleton)

install(TARGETS zlib RUNTIME DESTINATION libexec/bpf-capsule/examples/zlib)
if(BPF_CAPSULE_INSTALL_TEST_ARTIFACTS)
    install(FILES "${CMAKE_CURRENT_BINARY_DIR}/zlib_bpf_lib.o"
            DESTINATION libexec/bpf-capsule/examples/zlib
    )
endif()
install(
    FILES "${ZLIB_BPF_SOURCE_DIR}/LICENSE"
    DESTINATION share/licenses/bpf-capsule-examples
    RENAME zlib-LICENSE
)
