# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
execute_process(
    COMMAND "${LLVM_READELF}" -r "${OBJECT}"
    RESULT_VARIABLE status
    OUTPUT_VARIABLE relocations
)
if(NOT status EQUAL 0)
    message(FATAL_ERROR "llvm-readelf failed for ${OBJECT}")
endif()
if(relocations MATCHES "bpf_spill_scratch" OR relocations MATCHES "bpf_call_stack")
    message(
        FATAL_ERROR "native function without an exclusive fiber was relocated into fiber memory"
    )
endif()
