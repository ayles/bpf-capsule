# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
foreach(required LLVM_READELF LLVM_OBJDUMP OBJECT)
    if(NOT DEFINED ${required} OR "${${required}}" STREQUAL "")
        message(FATAL_ERROR "VerifyLargePressure.cmake needs -D${required}=...")
    endif()
endforeach()

execute_process(COMMAND "${LLVM_READELF}" --relocations "${OBJECT}"
    RESULT_VARIABLE result OUTPUT_VARIABLE relocations ERROR_VARIABLE error)
if(NOT result EQUAL 0)
    message(FATAL_ERROR "cannot inspect ${OBJECT}: ${error}")
endif()
if(relocations MATCHES "bpf_spill_scratch")
    message(FATAL_ERROR "large-pressure object revived the removed spill-scratch map")
endif()
if(NOT relocations MATCHES "bpf_call_stack"
   AND NOT relocations MATCHES "bpf_capsule_arena_control"
   AND NOT relocations MATCHES "heap[0-9]"
   AND NOT relocations MATCHES "bpf_heap_array")
    message(FATAL_ERROR "large-pressure object has no unified-memory backing")
endif()

execute_process(COMMAND "${LLVM_OBJDUMP}" --disassemble "${OBJECT}"
    RESULT_VARIABLE result OUTPUT_VARIABLE disassembly ERROR_VARIABLE error)
if(NOT result EQUAL 0)
    message(FATAL_ERROR "cannot disassemble ${OBJECT}: ${error}")
endif()
# llvm-objdump spells BPF memory immediates in hexadecimal. An access between
# 0x2000 and 0x7fff proves the physical transient crossed the former 8 KiB
# scratch ceiling without depending on compiler statistics or symbol names.
if(NOT disassembly MATCHES "\\+ 0x[234567][0-9a-f][0-9a-f][0-9a-f]\\)")
    message(FATAL_ERROR "large-pressure object did not prove a transient extent above 8 KiB")
endif()
