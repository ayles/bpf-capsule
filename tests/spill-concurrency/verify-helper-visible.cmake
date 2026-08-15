# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
execute_process(
    COMMAND
        "${LLC}" -O2 -mcpu=${BPF_CPU} -load "${PLUGIN}" -bpf-target=${TARGET_KERNEL}
        -bpf-unified-spill-pipeline -bpf-unified-spill-limit=${NATIVE_STACK_BYTES}
        --bpf-stack-size=262144 -bpf-unified-spill-report -verify-machineinstrs -filetype=obj -o
        "${OUTPUT}" "${SOURCE}"
    RESULT_VARIABLE result
    OUTPUT_VARIABLE stdout
    ERROR_VARIABLE stderr
)
set(log "${stdout}${stderr}")
if(NOT result EQUAL 0)
    message(FATAL_ERROR "helper-visible stack fixture failed to compile:\n${log}")
endif()
if(NOT log MATCHES "helper_visible frame [0-9]+ -> 400 .* unified 49")
    message(
        FATAL_ERROR
            "helper-visible buffer was not kept intact or unrelated suffix words stayed pinned:\n${log}"
    )
endif()

execute_process(
    COMMAND "${LLVM_READELF}" --relocations "${OUTPUT}"
    RESULT_VARIABLE result
    OUTPUT_VARIABLE relocations
    ERROR_VARIABLE error
)
if(NOT result EQUAL 0)
    message(FATAL_ERROR "cannot inspect ${OUTPUT}: ${error}")
endif()
if(NOT relocations MATCHES "bpf_call_stack")
    message(FATAL_ERROR "helper-visible fixture did not relocate scalar spills to unified memory")
endif()
