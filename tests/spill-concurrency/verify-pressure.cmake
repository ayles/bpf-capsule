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
    message(FATAL_ERROR "large-pressure regression still uses bpf_spill_scratch")
endif()
if(NOT relocations MATCHES "bpf_call_stack"
   AND NOT relocations MATCHES "bpf_capsule_arena_control"
   AND NOT relocations MATCHES "heap[0-9]"
   AND NOT relocations MATCHES "bpf_heap_array"
)
    message(FATAL_ERROR "large-pressure regression has no unified-memory backing")
endif()

execute_process(
    COMMAND "${LLVM_OBJDUMP}" --disassemble "${OBJECT}"
    RESULT_VARIABLE result
    OUTPUT_VARIABLE disassembly
    ERROR_VARIABLE error
)
if(NOT result EQUAL 0)
    message(FATAL_ERROR "cannot disassemble ${OBJECT}: ${error}")
endif()
# llvm-objdump prints BPF memory immediates in hexadecimal. A positive offset
# from 0x2000 through 0x7fff proves that the relocated transient extent crossed
# the old fixed 8192-byte scratch ceiling. (The compiler caps a fiber stack at
# 2 MiB, but BPF's signed 16-bit memory immediate keeps this direct form below
# 0x8000.)
if(NOT disassembly MATCHES "\\+ 0x[234567][0-9a-f][0-9a-f][0-9a-f]\\)")
    message(FATAL_ERROR "large-pressure regression did not prove a transient extent above 8 KiB")
endif()
