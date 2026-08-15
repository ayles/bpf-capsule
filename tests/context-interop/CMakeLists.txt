# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
foreach(MODE borrowed yield)
    bpf_capsule_bitcode(
        CONTEXT_INTEROP_${MODE}_BC
        COMPILE_OPTIONS -g
        SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/context_interop_${MODE}_bpf.c
    )
    bpf_capsule_object(
        context_interop_${MODE}_bpf_output
        OUTPUT context_interop_${MODE}_bpf.o
        BITCODE ${CONTEXT_INTEROP_${MODE}_BC}
    )
endforeach()

bpf_capsule_bitcode(
    CONTEXT_INTEROP_SCALAR_CONTEXT_BC
    SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/unsupported-scalar-context.c
    COMPILE_OPTIONS -g
)
# The contract input needs the runtime linked in, exactly like a real
# object: the passes validate the runtime's presence before diagnosing the
# scalar-context misuse this test pins.
bpf_capsule_runtime_bitcode(
    CONTEXT_INTEROP_RUNTIME_BC
)
set(CONTEXT_INTEROP_SCALAR_LINKED_BC "${CMAKE_CURRENT_BINARY_DIR}/scalar-context-linked.bc")
add_custom_command(
    OUTPUT "${CONTEXT_INTEROP_SCALAR_LINKED_BC}"
    COMMAND "${BPF_CAPSULE_LLVM_LINK}" -o "${CONTEXT_INTEROP_SCALAR_LINKED_BC}"
            ${CONTEXT_INTEROP_SCALAR_CONTEXT_BC} ${CONTEXT_INTEROP_RUNTIME_BC}
    DEPENDS ${CONTEXT_INTEROP_SCALAR_CONTEXT_BC} ${CONTEXT_INTEROP_RUNTIME_BC}
    COMMENT "Link scalar/context contract input"
    VERBATIM
)
add_custom_target(
    context_interop_scalar_context_contract ALL
    COMMAND
        "${CMAKE_COMMAND}" "-DOPT=${BPF_CAPSULE_OPT}" "-DPLUGIN=$<TARGET_FILE:bpf_capsule_pass>"
        "-DINPUT=${CONTEXT_INTEROP_SCALAR_LINKED_BC}" -P
        "${CMAKE_CURRENT_SOURCE_DIR}/verify-negative.cmake"
    DEPENDS bpf_capsule_pass "${CONTEXT_INTEROP_SCALAR_LINKED_BC}"
    COMMENT "Scalar/context dispatch contract"
    VERBATIM
)

add_executable(context_interop_test_host context_interop_host.c)
target_include_directories(
    context_interop_test_host PRIVATE ${BPF_CAPSULE_INCLUDE_DIRS} "${CMAKE_CURRENT_SOURCE_DIR}"
)
target_link_libraries(context_interop_test_host PkgConfig::LibBpf)
add_dependencies(
    context_interop_test_host context_interop_borrowed_bpf_output context_interop_yield_bpf_output
)

install(TARGETS context_interop_test_host
        RUNTIME DESTINATION libexec/bpf-capsule/tests/context-interop
)
install(FILES "${CMAKE_CURRENT_BINARY_DIR}/context_interop_borrowed_bpf.o"
              "${CMAKE_CURRENT_BINARY_DIR}/context_interop_yield_bpf.o"
        DESTINATION libexec/bpf-capsule/tests/context-interop
)
