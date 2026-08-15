# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
bpf_capsule_bitcode(
    FIB_BC
    SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/fib_bpf.c
    INCLUDE_DIRECTORIES ${CMAKE_CURRENT_SOURCE_DIR}
    COMPILE_OPTIONS -g
)

bpf_capsule_object(
    fib_bpf_output
    OUTPUT fib_bpf.o
    BITCODE ${FIB_BC}
)

bpf_capsule_skeleton(
    fib_skeleton
    OUTPUT "${CMAKE_CURRENT_BINARY_DIR}/fib.skel.h"
    OBJECT "${CMAKE_CURRENT_BINARY_DIR}/fib_bpf.o"
    NAME fib
    DEPENDS fib_bpf_output
)

add_executable(fib fib_host.c "${CMAKE_CURRENT_BINARY_DIR}/fib.skel.h")
target_include_directories(
    fib PRIVATE "${CMAKE_CURRENT_BINARY_DIR}" ${BPF_CAPSULE_INCLUDE_DIRS}
                "${CMAKE_CURRENT_SOURCE_DIR}"
)
target_compile_options(fib PRIVATE -Wall -Wextra)
target_link_libraries(fib PkgConfig::LibBpf)
add_dependencies(fib fib_skeleton)

install(TARGETS fib RUNTIME DESTINATION libexec/bpf-capsule/examples/fib)
