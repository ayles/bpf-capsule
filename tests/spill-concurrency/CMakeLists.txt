# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
set(PHYSICAL_SPILL_OBJECT "${CMAKE_CURRENT_BINARY_DIR}/physical_spill_bpf.o")
add_custom_command(
    OUTPUT "${PHYSICAL_SPILL_OBJECT}"
    COMMAND
        "${BPF_CAPSULE_LLC}" -O2 -mcpu=${_BPF_CAPSULE_CPU} -load $<TARGET_FILE:bpf_capsule_pass>
        -bpf-target=${BPF_CAPSULE_TARGET_KERNEL} -bpf-unified-spill-pipeline
        -bpf-unified-spill-limit=${_BPF_CAPSULE_NATIVE_STACK_BYTES}
        --bpf-stack-size=${BPF_CAPSULE_FIBER_STACK_BYTES} -verify-machineinstrs -filetype=obj -o
        "${PHYSICAL_SPILL_OBJECT}" "${CMAKE_CURRENT_SOURCE_DIR}/physical.ll"
    COMMAND "${CMAKE_COMMAND}" "-DLLVM_READELF=${BPF_CAPSULE_LLVM_READELF}"
            "-DOBJECT=${PHYSICAL_SPILL_OBJECT}" -P "${CMAKE_CURRENT_SOURCE_DIR}/verify.cmake"
    DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/physical.ll" "${CMAKE_CURRENT_SOURCE_DIR}/verify.cmake"
            bpf_capsule_pass
    COMMENT "BPF physical-spill concurrency fixture"
    VERBATIM
)
add_custom_target(physical_spill_bpf_output ALL DEPENDS "${PHYSICAL_SPILL_OBJECT}")

set(NATIVE_ZERO_OBJECT "${CMAKE_CURRENT_BINARY_DIR}/native_zero_bpf.o")
add_custom_command(
    OUTPUT "${NATIVE_ZERO_OBJECT}"
    COMMAND
        "${BPF_CAPSULE_LLC}" -O2 -mcpu=${_BPF_CAPSULE_CPU} -load $<TARGET_FILE:bpf_capsule_pass>
        -bpf-target=${BPF_CAPSULE_TARGET_KERNEL} -bpf-unified-spill-pipeline
        -bpf-unified-spill-limit=0 --bpf-stack-size=${BPF_CAPSULE_FIBER_STACK_BYTES}
        -verify-machineinstrs -filetype=obj -o "${NATIVE_ZERO_OBJECT}"
        "${CMAKE_CURRENT_SOURCE_DIR}/native-zero.ll"
    COMMAND
        "${CMAKE_COMMAND}" "-DLLVM_READELF=${BPF_CAPSULE_LLVM_READELF}"
        "-DOBJECT=${NATIVE_ZERO_OBJECT}" -P "${CMAKE_CURRENT_SOURCE_DIR}/verify-native-zero.cmake"
    DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/native-zero.ll"
            "${CMAKE_CURRENT_SOURCE_DIR}/verify-native-zero.cmake" bpf_capsule_pass
    COMMENT "BPF zero-budget native-stack contract fixture"
    VERBATIM
)
add_custom_target(native_zero_bpf_output ALL DEPENDS "${NATIVE_ZERO_OBJECT}")

add_custom_target(
    oversized_native_error_contract ALL
    COMMAND
        "${CMAKE_COMMAND}" "-DLLC=${BPF_CAPSULE_LLC}" "-DPLUGIN=$<TARGET_FILE:bpf_capsule_pass>"
        "-DBPF_CPU=${_BPF_CAPSULE_CPU}" "-DTARGET_KERNEL=${BPF_CAPSULE_TARGET_KERNEL}"
        "-DNATIVE_STACK_BYTES=${_BPF_CAPSULE_NATIVE_STACK_BYTES}"
        "-DSOURCE=${CMAKE_CURRENT_SOURCE_DIR}/oversized-native.ll"
        "-DOUTPUT=${CMAKE_CURRENT_BINARY_DIR}/oversized-native.o" -P
        "${CMAKE_CURRENT_SOURCE_DIR}/verify-oversized-native.cmake"
    DEPENDS bpf_capsule_pass "${CMAKE_CURRENT_SOURCE_DIR}/oversized-native.ll"
            "${CMAKE_CURRENT_SOURCE_DIR}/verify-oversized-native.cmake"
    COMMENT "Reject oversized native BPF frames after spill-analysis bailouts"
    VERBATIM
)

set(HELPER_VISIBLE_IR "${CMAKE_CURRENT_BINARY_DIR}/helper-visible.ll")
add_custom_command(
    OUTPUT "${HELPER_VISIBLE_IR}"
    COMMAND "${CMAKE_COMMAND}" "-DOUTPUT=${HELPER_VISIBLE_IR}" -DWORD_COUNT=48 -P
            "${CMAKE_CURRENT_SOURCE_DIR}/generate-helper-visible.cmake"
    DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/generate-helper-visible.cmake"
    COMMENT "Generate helper-visible stack-buffer fixture"
    VERBATIM
)
add_custom_target(
    helper_visible_stack_contract ALL
    COMMAND
        "${CMAKE_COMMAND}" "-DLLC=${BPF_CAPSULE_LLC}" "-DLLVM_READELF=${BPF_CAPSULE_LLVM_READELF}"
        "-DPLUGIN=$<TARGET_FILE:bpf_capsule_pass>" "-DBPF_CPU=${_BPF_CAPSULE_CPU}"
        "-DTARGET_KERNEL=${BPF_CAPSULE_TARGET_KERNEL}"
        "-DNATIVE_STACK_BYTES=${_BPF_CAPSULE_NATIVE_STACK_BYTES}" "-DSOURCE=${HELPER_VISIBLE_IR}"
        "-DOUTPUT=${CMAKE_CURRENT_BINARY_DIR}/helper-visible.o" -P
        "${CMAKE_CURRENT_SOURCE_DIR}/verify-helper-visible.cmake"
    DEPENDS bpf_capsule_pass "${HELPER_VISIBLE_IR}"
            "${CMAKE_CURRENT_SOURCE_DIR}/verify-helper-visible.cmake"
    COMMENT "Keep complete helper-visible buffers on the native BPF stack"
    VERBATIM
)

set(LARGE_PHYSICAL_IR "${CMAKE_CURRENT_BINARY_DIR}/large-physical.ll")
add_custom_command(
    OUTPUT "${LARGE_PHYSICAL_IR}"
    COMMAND "${CMAKE_COMMAND}" "-DOUTPUT=${LARGE_PHYSICAL_IR}" -DWORD_COUNT=5000 -P
            "${CMAKE_CURRENT_SOURCE_DIR}/generate-large-physical.cmake"
    DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/generate-large-physical.cmake"
    COMMENT "Generate direct post-RA >8 KiB spill fixture"
    VERBATIM
)
set(LARGE_PHYSICAL_OBJECT "${CMAKE_CURRENT_BINARY_DIR}/large_physical_bpf.o")
add_custom_command(
    OUTPUT "${LARGE_PHYSICAL_OBJECT}"
    COMMAND
        "${BPF_CAPSULE_LLC}" -O2 -mcpu=${_BPF_CAPSULE_CPU} -load $<TARGET_FILE:bpf_capsule_pass>
        -bpf-target=${BPF_CAPSULE_TARGET_KERNEL} -bpf-unified-spill-pipeline
        -bpf-unified-spill-limit=${_BPF_CAPSULE_NATIVE_STACK_BYTES}
        --bpf-stack-size=${BPF_CAPSULE_FIBER_STACK_BYTES} -verify-machineinstrs -filetype=obj -o
        "${LARGE_PHYSICAL_OBJECT}" "${LARGE_PHYSICAL_IR}"
    COMMAND
        "${CMAKE_COMMAND}" "-DLLVM_READELF=${BPF_CAPSULE_LLVM_READELF}"
        "-DLLVM_OBJDUMP=${BPF_CAPSULE_LLVM_OBJDUMP}" "-DOBJECT=${LARGE_PHYSICAL_OBJECT}" -P
        "${CMAKE_CURRENT_SOURCE_DIR}/verify-large-physical.cmake"
    DEPENDS "${LARGE_PHYSICAL_IR}" "${CMAKE_CURRENT_SOURCE_DIR}/verify-large-physical.cmake"
            bpf_capsule_pass
    COMMENT "BPF direct post-RA >8 KiB spill fixture"
    VERBATIM
)
add_custom_target(large_physical_bpf_output ALL DEPENDS "${LARGE_PHYSICAL_OBJECT}")

# Generate rather than check in 2,400 repetitive statements. This is the
# source-level adversarial case: all 1,200 volatile-loaded values remain live
# until a later key load, producing more than 8 KiB of legitimate late spills.
set(LARGE_PRESSURE_SOURCE "${CMAKE_CURRENT_BINARY_DIR}/large-pressure.c")
add_custom_command(
    OUTPUT "${LARGE_PRESSURE_SOURCE}"
    COMMAND "${CMAKE_COMMAND}" "-DOUTPUT=${LARGE_PRESSURE_SOURCE}" -DVALUE_COUNT=1200 -P
            "${CMAKE_CURRENT_SOURCE_DIR}/generate-pressure.cmake"
    DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/generate-pressure.cmake"
    COMMENT "Generate adversarial >8 KiB spill-pressure source"
    VERBATIM
)
bpf_capsule_bitcode(
    LARGE_PRESSURE_BC
    COMPILE_OPTIONS -g
    SOURCES "${LARGE_PRESSURE_SOURCE}"
)
set(LARGE_PRESSURE_OBJECT "${CMAKE_CURRENT_BINARY_DIR}/large_pressure_bpf.o")
bpf_capsule_object(
    large_pressure_bpf_output
    OUTPUT "${LARGE_PRESSURE_OBJECT}"
    BITCODE ${LARGE_PRESSURE_BC}
)
set(LARGE_PRESSURE_STAMP "${CMAKE_CURRENT_BINARY_DIR}/large_pressure_verified.stamp")
add_custom_command(
    OUTPUT "${LARGE_PRESSURE_STAMP}"
    COMMAND
        "${CMAKE_COMMAND}" "-DLLVM_READELF=${BPF_CAPSULE_LLVM_READELF}"
        "-DLLVM_OBJDUMP=${BPF_CAPSULE_LLVM_OBJDUMP}" "-DOBJECT=${LARGE_PRESSURE_OBJECT}" -P
        "${CMAKE_CURRENT_SOURCE_DIR}/verify-pressure.cmake"
    COMMAND "${CMAKE_COMMAND}" -E touch "${LARGE_PRESSURE_STAMP}"
    DEPENDS "${LARGE_PRESSURE_OBJECT}" "${CMAKE_CURRENT_SOURCE_DIR}/verify-pressure.cmake"
    COMMENT "Verify adversarial >8 KiB spills use unified fiber memory"
    VERBATIM
)
add_custom_target(large_pressure_regression ALL DEPENDS "${LARGE_PRESSURE_STAMP}")

add_executable(physical_spill_host physical_host.c)
target_include_directories(physical_spill_host PRIVATE ${BPF_CAPSULE_INCLUDE_DIRS})
target_link_libraries(physical_spill_host PkgConfig::LibBpf pthread)
add_dependencies(physical_spill_host physical_spill_bpf_output)

install(TARGETS physical_spill_host RUNTIME DESTINATION libexec/bpf-capsule/tests/spill-concurrency)
install(FILES "${PHYSICAL_SPILL_OBJECT}" DESTINATION libexec/bpf-capsule/tests/spill-concurrency)
