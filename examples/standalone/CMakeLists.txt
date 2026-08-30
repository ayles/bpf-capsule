# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
# A complete consumer of an installed BPF Capsule package.
cmake_minimum_required(VERSION 3.21)
project(BpfCapsuleStandaloneExample C)

find_package(BpfCapsule CONFIG REQUIRED)

find_package(PkgConfig REQUIRED)
pkg_check_modules(LibBpf libbpf>=1.4.0 REQUIRED IMPORTED_TARGET)
set(BPF_CAPSULE_LIBBPF_TARGET PkgConfig::LibBpf)

bpf_capsule_bitcode(
    expr_bc
    SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/expr_bpf.c ${CMAKE_CURRENT_SOURCE_DIR}/expr.c
    COMPILE_OPTIONS -g
)
bpf_capsule_object(
    expr_bpf
    OUTPUT expr.bpf.o
    BITCODE ${expr_bc}
)
bpf_capsule_skeleton(
    expr_skeleton
    OUTPUT "${CMAKE_CURRENT_BINARY_DIR}/expr.skel.h"
    OBJECT "${CMAKE_CURRENT_BINARY_DIR}/expr.bpf.o"
    NAME expr
    DEPENDS expr_bpf
)

add_executable(expr expr_host.c "${CMAKE_CURRENT_BINARY_DIR}/expr.skel.h")
target_include_directories(expr PRIVATE "${CMAKE_CURRENT_BINARY_DIR}" ${BPF_CAPSULE_INCLUDE_DIRS})
target_compile_options(expr PRIVATE -Wall -Wextra)
target_link_libraries(expr ${BPF_CAPSULE_HOST_TARGET})
add_dependencies(expr expr_skeleton)
