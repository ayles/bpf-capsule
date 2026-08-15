# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
execute_process(
    COMMAND "${LLVM_READELF}" --relocations "${OBJECT}"
    RESULT_VARIABLE result
    OUTPUT_VARIABLE relocations
    ERROR_VARIABLE error
)
if(NOT result EQUAL 0)
    message(FATAL_ERROR "cannot inspect ${OBJECT}: ${error}")
endif()
if(relocations MATCHES "bpf_spill_scratch")
    message(FATAL_ERROR "physical-spill fixture still uses the removed spill-scratch map")
endif()
if(NOT relocations MATCHES "bpf_call_stack")
    message(FATAL_ERROR "physical-spill fixture does not relocate into the unified fiber stack")
endif()
