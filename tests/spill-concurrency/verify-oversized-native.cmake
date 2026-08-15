# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
execute_process(
    COMMAND
        "${LLC}" -O2 -mcpu=${BPF_CPU} -load "${PLUGIN}" -bpf-target=${TARGET_KERNEL}
        -bpf-unified-spill-pipeline -bpf-unified-spill-limit=${NATIVE_STACK_BYTES}
        --bpf-stack-size=262144 -verify-machineinstrs -filetype=obj -o "${OUTPUT}" "${SOURCE}"
    RESULT_VARIABLE status
    OUTPUT_VARIABLE output
    ERROR_VARIABLE error
)
set(log "${output}${error}")
if(status EQUAL 0)
    message(FATAL_ERROR "oversized native frame compiled successfully")
endif()
if(NOT log MATCHES "exceeds the 512-byte BPF stack")
    message(FATAL_ERROR "oversized native frame missed the explicit diagnostic:\n${log}")
endif()
if(log MATCHES "PLEASE submit a bug report" OR log MATCHES "Stack dump:")
    message(FATAL_ERROR "oversized native frame crashed instead of failing cleanly:\n${log}")
endif()
