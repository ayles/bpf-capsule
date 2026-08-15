# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
# Standalone BPF Capsule consumer: the project a user copies into their own
# repository. It builds against an installed package only — nothing here
# reaches back into the BPF Capsule source tree, and it is deliberately not
# part of the main build.
cmake_minimum_required(VERSION 3.21)
project(BpfCapsuleStandaloneExample C)

# Provides the pass plugin target, the public pipeline helpers used below,
# and the installed bpf_capsule.c include path. Point CMAKE_PREFIX_PATH at
# the BPF Capsule install prefix if it is not already searched.
find_package(BpfCapsule CONFIG REQUIRED)

# libbpf serves both sides: bpf_helpers.h for the BPF translation units, and
# the loader library for the host executable.
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

# Native reference: the same evaluator sources, so both sides run identical
# code and the host can require bit-for-bit equal results.
add_executable(expr expr_host.c expr.c "${CMAKE_CURRENT_BINARY_DIR}/expr.skel.h")
target_include_directories(expr PRIVATE "${CMAKE_CURRENT_BINARY_DIR}" ${BPF_CAPSULE_INCLUDE_DIRS})
target_compile_options(expr PRIVATE -Wall -Wextra)
target_link_libraries(expr PkgConfig::LibBpf)
add_dependencies(expr expr_skeleton)
