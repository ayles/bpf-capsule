# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
find_program(BPF_CAPSULE_BASH bash REQUIRED)
add_custom_target(
    atomic_contract ALL
    COMMAND "${BPF_CAPSULE_BASH}" "${CMAKE_CURRENT_SOURCE_DIR}/check.sh" "${BPF_CAPSULE_OPT}"
            "$<TARGET_FILE:bpf_capsule_pass>"
    DEPENDS bpf_capsule_pass
    VERBATIM
)

bpf_capsule_bitcode(
    ATOMIC_RUNTIME_BC
    COMPILE_DEFINITIONS BPF_CAPSULE_MAX_FIBERS=2
    COMPILE_OPTIONS -g
    SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/native_bpf.c
)
bpf_capsule_object(
    atomic_runtime_bpf_output
    OUTPUT atomic_runtime_bpf.o
    BITCODE ${ATOMIC_RUNTIME_BC}
    RUNTIME_COMPILE_DEFINITIONS BPF_CAPSULE_MAX_FIBERS=2
)

add_custom_target(
    atomic_isa_contract ALL
    COMMAND
        "${CMAKE_COMMAND}" "-DLLVM_OBJDUMP=${BPF_CAPSULE_LLVM_OBJDUMP}"
        "-DOBJECT=${CMAKE_CURRENT_BINARY_DIR}/atomic_runtime_bpf.o"
        "-DTARGET_KERNEL=${BPF_CAPSULE_TARGET_KERNEL}" -P
        "${CMAKE_CURRENT_SOURCE_DIR}/verify-isa.cmake"
    DEPENDS atomic_runtime_bpf_output
    COMMENT "BPF native and managed atomic ISA contract"
    VERBATIM
)

add_executable(atomic_runtime_host native_host.c)
target_include_directories(
    atomic_runtime_host PRIVATE ${BPF_CAPSULE_INCLUDE_DIRS} "${CMAKE_CURRENT_SOURCE_DIR}"
)
target_link_libraries(atomic_runtime_host PkgConfig::LibBpf pthread)
add_dependencies(atomic_runtime_host atomic_runtime_bpf_output)

install(TARGETS atomic_runtime_host RUNTIME DESTINATION libexec/bpf-capsule/tests/atomics)
install(FILES "${CMAKE_CURRENT_BINARY_DIR}/atomic_runtime_bpf.o"
        DESTINATION libexec/bpf-capsule/tests/atomics
)
