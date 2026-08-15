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
        e3dc0a85b7032e98380dec011bc8f2c2ee0d8fca
        MARKER
        inflate.c
    )
    if(NOT fetched_zlib)
        message(STATUS "zlib example: upstream source unavailable, skipping")
        return()
    endif()
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
    INCLUDE_DIRECTORIES ${ZLIB_BPF_SOURCE_DIR}
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

# Matched host baseline: the same generic upstream inflate sources as the BPF
# object, compiled natively by the host compiler for the host architecture
# with the same optimization and loop unrolling policy.  Z_PREFIX gives the
# copy a private namespace so the benchmark can also link the distribution
# zlib (which may select platform SIMD/assembly) for input compression and
# comparison.
add_library(zlib_scalar_native STATIC EXCLUDE_FROM_ALL ${ZLIB_SRC} ${ZLIB_BPF_SOURCE_DIR}/uncompr.c)
target_include_directories(zlib_scalar_native PRIVATE ${ZLIB_BPF_SOURCE_DIR})
target_compile_definitions(zlib_scalar_native PRIVATE Z_PREFIX)
target_compile_options(zlib_scalar_native PRIVATE -O2 -fno-unroll-loops -fno-builtin)

add_executable(zlib zlib_host.c "${CMAKE_CURRENT_BINARY_DIR}/zlib.skel.h")
target_include_directories(zlib PRIVATE "${CMAKE_CURRENT_BINARY_DIR}" ${BPF_CAPSULE_INCLUDE_DIRS})
target_compile_options(zlib PRIVATE -Wall -Wextra)
target_link_libraries(zlib PkgConfig::LibBpf ZLIB::ZLIB zlib_scalar_native)
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
