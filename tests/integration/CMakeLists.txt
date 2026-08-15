# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
bpf_capsule_bitcode(
    COMPILER_TEST_BC
    SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/compiler_bpf.c ${BPF_CAPSULE_LIBC_DIR}/freestanding.c
            ${BPF_CAPSULE_LIBC_DIR}/tlsf.c ${BPF_CAPSULE_LIBC_DIR}/softfloat.c
    INCLUDE_DIRECTORIES ${BPF_CAPSULE_LIBC_DIR} ${BPF_CAPSULE_LIBC_DIR}/include
    COMPILE_DEFINITIONS BPF_CAPSULE_MAX_FIBERS=2 BPF_CAPSULE_DRIVE_LEVEL=16
    COMPILE_OPTIONS -g
)
bpf_capsule_object(
    compiler_test_bpf_output
    OUTPUT compiler_test_bpf.o
    BITCODE ${COMPILER_TEST_BC}
    RUNTIME_COMPILE_DEFINITIONS BPF_CAPSULE_MAX_FIBERS=2 BPF_CAPSULE_DRIVE_LEVEL=16
)

add_executable(compiler_test_host compiler_host.c)
target_include_directories(compiler_test_host PRIVATE ${BPF_CAPSULE_INCLUDE_DIRS})
target_link_libraries(compiler_test_host PkgConfig::LibBpf)
target_link_libraries(compiler_test_host pthread)
add_dependencies(compiler_test_host compiler_test_bpf_output)

# The arena tier injects a once-only initializer into every entry. Keep this
# fixture separate from the broad compiler integration object so a regression
# reports the exact fixed-alloca/prologue contract that used to fail in llc.
if(BPF_CAPSULE_HAS_ARENA)
    bpf_capsule_bitcode(
        ARENA_PROLOGUE_BC
        COMPILE_OPTIONS -g
        SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/arena_prologue_bpf.c
    )
    bpf_capsule_object(
        arena_prologue_bpf_output
        OUTPUT arena_prologue_bpf.o
        BITCODE ${ARENA_PROLOGUE_BC}
    )
    add_custom_target(
        arena_prologue_isa_contract ALL
        COMMAND
            "${CMAKE_COMMAND}" "-DLLVM_OBJDUMP=${BPF_CAPSULE_LLVM_OBJDUMP}"
            "-DOBJECT=${CMAKE_CURRENT_BINARY_DIR}/arena_prologue_bpf.o"
            "-DTARGET_KERNEL=${BPF_CAPSULE_TARGET_KERNEL}" -P
            "${CMAKE_CURRENT_SOURCE_DIR}/verify-arena-isa.cmake"
        DEPENDS arena_prologue_bpf_output
        COMMENT "BPF arena signed-load compatibility contract"
        VERBATIM
    )
endif()

# Exercise the exact downstream reference sources in both release profiles.
# examples/standalone remains an independent find_package() project; these
# targets only make its runtime behavior part of the in-tree regression gate.
bpf_capsule_bitcode(
    STANDALONE_EXPR_BC
    SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/../../examples/standalone/expr_bpf.c
            ${CMAKE_CURRENT_SOURCE_DIR}/../../examples/standalone/expr.c
    INCLUDE_DIRECTORIES ${CMAKE_CURRENT_SOURCE_DIR}/../../examples/standalone
    COMPILE_OPTIONS -g
)
bpf_capsule_object(
    standalone_expr_bpf_output
    OUTPUT standalone_expr_bpf.o
    BITCODE ${STANDALONE_EXPR_BC}
)
bpf_capsule_skeleton(
    standalone_expr_skeleton
    OUTPUT "${CMAKE_CURRENT_BINARY_DIR}/expr.skel.h"
    OBJECT "${CMAKE_CURRENT_BINARY_DIR}/standalone_expr_bpf.o"
    NAME expr
    DEPENDS standalone_expr_bpf_output
)

add_executable(
    standalone_expr_host
    ${CMAKE_CURRENT_SOURCE_DIR}/../../examples/standalone/expr_host.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../examples/standalone/expr.c
    "${CMAKE_CURRENT_BINARY_DIR}/expr.skel.h"
)
target_include_directories(
    standalone_expr_host PRIVATE "${CMAKE_CURRENT_BINARY_DIR}" ${BPF_CAPSULE_INCLUDE_DIRS}
                                 ${CMAKE_CURRENT_SOURCE_DIR}/../../examples/standalone
)
target_link_libraries(standalone_expr_host PkgConfig::LibBpf)
add_dependencies(standalone_expr_host standalone_expr_skeleton)

# The full Nix matrix consumes installed, immutable artifacts rather than a
# mutable CMake build tree. Keeping the same relative layout lets the local
# and VM runners share one case description.
install(TARGETS compiler_test_host standalone_expr_host
        RUNTIME DESTINATION libexec/bpf-capsule/tests/integration
)
install(FILES "${CMAKE_CURRENT_BINARY_DIR}/compiler_test_bpf.o"
              "${CMAKE_CURRENT_BINARY_DIR}/standalone_expr_bpf.o"
        DESTINATION libexec/bpf-capsule/tests/integration
)
