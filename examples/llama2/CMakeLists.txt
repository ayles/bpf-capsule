# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
# Transformer inference in the kernel: llama2.c through the same pipeline.
# Source is fetched below unless LLAMA2_BPF_SOURCE_DIR is supplied. Checkpoint
# data is always supplied by the user and is never downloaded by the build.
set(LLAMA2_BPF_SOURCE_DIR
    ""
    CACHE PATH "use an existing llama2.c source tree"
)
if(NOT LLAMA2_BPF_SOURCE_DIR OR NOT EXISTS "${LLAMA2_BPF_SOURCE_DIR}/run.c")
    fetch_example_source(
        fetched_llama2
        bpf_capsule_llama2
        GIT_REPOSITORY
        https://github.com/karpathy/llama2.c.git
        GIT_TAG
        350e04fe35433e6d2941dce5a1f53308f87058eb
        MARKER
        run.c
    )
    if(NOT fetched_llama2)
        message(STATUS "llama2 example: upstream source unavailable, skipping")
        return()
    endif()
    set(LLAMA2_BPF_SOURCE_DIR "${fetched_llama2}")
endif()

set(LLAMA2_BPF_INCLUDE_DIRECTORIES ${BPF_CAPSULE_LIBC_DIR} ${BPF_CAPSULE_LIBC_DIR}/include
                                   ${LLAMA2_BPF_SOURCE_DIR}
)

bpf_capsule_bitcode(
    LLAMA2_BC
    SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/llama2_bpf.c ${BPF_CAPSULE_LIBC_DIR}/freestanding.c
            ${BPF_CAPSULE_LIBC_DIR}/tlsf.c ${BPF_CAPSULE_LIBC_DIR}/softfloat.c
            ${BPF_CAPSULE_LIBC_DIR}/mathfns.c
    INCLUDE_DIRECTORIES ${LLAMA2_BPF_INCLUDE_DIRECTORIES}
    COMPILE_OPTIONS -Wno-implicit-function-declaration -g
)

bpf_capsule_object(
    llama2_bpf_lib_output
    OUTPUT llama2_bpf_lib.o
    BITCODE ${LLAMA2_BC}
)
bpf_capsule_skeleton(
    llama2_skeleton
    OUTPUT "${CMAKE_CURRENT_BINARY_DIR}/llama2.skel.h"
    OBJECT "${CMAKE_CURRENT_BINARY_DIR}/llama2_bpf_lib.o"
    NAME llama2
    DEPENDS llama2_bpf_lib_output
)

add_executable(llama2 llama2_host.c "${CMAKE_CURRENT_BINARY_DIR}/llama2.skel.h")
target_include_directories(
    llama2 PRIVATE "${CMAKE_CURRENT_BINARY_DIR}" ${BPF_CAPSULE_INCLUDE_DIRS}
                   ${LLAMA2_BPF_SOURCE_DIR}
)
target_compile_options(llama2 PRIVATE -Wall -Wextra)
target_link_libraries(llama2 PkgConfig::LibBpf m)
add_dependencies(llama2 llama2_skeleton)

# The int8 path: the same model quantized to 8 bits with one scale per group
# of 64. Most of the arithmetic becomes integer dot products, which is what a
# machine with no floating-point unit wants — the fp32 build above spends
# nearly all its time in soft-float.
bpf_capsule_bitcode(
    LLAMA2Q_BC
    SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/llama2q_bpf.c ${BPF_CAPSULE_LIBC_DIR}/freestanding.c
            ${BPF_CAPSULE_LIBC_DIR}/tlsf.c ${BPF_CAPSULE_LIBC_DIR}/softfloat.c
            ${BPF_CAPSULE_LIBC_DIR}/mathfns.c
    INCLUDE_DIRECTORIES ${LLAMA2_BPF_INCLUDE_DIRECTORIES}
    COMPILE_OPTIONS -Wno-implicit-function-declaration -g
)

bpf_capsule_object(
    llama2q_bpf_lib_output
    OUTPUT llama2q_bpf_lib.o
    BITCODE ${LLAMA2Q_BC}
)
bpf_capsule_skeleton(
    llama2q_skeleton
    OUTPUT "${CMAKE_CURRENT_BINARY_DIR}/llama2q.skel.h"
    OBJECT "${CMAKE_CURRENT_BINARY_DIR}/llama2q_bpf_lib.o"
    NAME llama2q
    DEPENDS llama2q_bpf_lib_output
)

add_executable(llama2q llama2q_host.c "${CMAKE_CURRENT_BINARY_DIR}/llama2q.skel.h")
target_include_directories(
    llama2q PRIVATE "${CMAKE_CURRENT_BINARY_DIR}" ${BPF_CAPSULE_INCLUDE_DIRS}
                    ${LLAMA2_BPF_SOURCE_DIR}
)
target_compile_options(llama2q PRIVATE -Wall -Wextra)
target_link_libraries(llama2q PkgConfig::LibBpf m)
add_dependencies(llama2q llama2q_skeleton)

install(TARGETS llama2 llama2q RUNTIME DESTINATION libexec/bpf-capsule/examples/llama2)
if(BPF_CAPSULE_INSTALL_TEST_ARTIFACTS)
    install(FILES "${CMAKE_CURRENT_BINARY_DIR}/llama2_bpf_lib.o"
                  "${CMAKE_CURRENT_BINARY_DIR}/llama2q_bpf_lib.o"
            DESTINATION libexec/bpf-capsule/examples/llama2
    )
endif()
install(
    FILES "${LLAMA2_BPF_SOURCE_DIR}/LICENSE"
    DESTINATION share/licenses/bpf-capsule-examples
    RENAME llama2.c-LICENSE
)
