# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
execute_process(
    COMMAND "${LLVM_OBJDUMP}" -d --disassemble-symbols=atomic_runtime_increment "${OBJECT}"
    RESULT_VARIABLE native_status
    OUTPUT_VARIABLE native_disassembly
    ERROR_VARIABLE native_error
)
if(NOT native_status EQUAL 0)
    message(FATAL_ERROR "cannot disassemble ${OBJECT}: ${native_error}")
endif()
foreach(width IN ITEMS 32 64)
    string(FIND "${native_disassembly}" "lock *(u${width} *)" native_atomic)
    if(native_atomic EQUAL -1)
        message(FATAL_ERROR "native u${width} atomic RMW is absent from ${OBJECT}")
    endif()
endforeach()

# Managed relaxed atomics are deliberately one naturally-sized BPF memory
# instruction. On the fixed tier the source reaches the cells through a stored
# virtual pointer, so these are dynamic accessors rather than direct globals.
if(TARGET_KERNEL STREQUAL "5.15")
    foreach(width IN ITEMS 8 16 32 64)
        foreach(operation IN ITEMS load store)
            execute_process(
                COMMAND "${LLVM_OBJDUMP}" -d "--disassemble-symbols=bpf_heap_${operation}${width}"
                        "${OBJECT}"
                RESULT_VARIABLE accessor_status
                OUTPUT_VARIABLE accessor_disassembly
                ERROR_VARIABLE accessor_error
            )
            if(NOT accessor_status EQUAL 0)
                message(FATAL_ERROR "cannot disassemble u${width} ${operation}: ${accessor_error}")
            endif()
            string(FIND "${accessor_disassembly}" "<bpf_heap_${operation}${width}>" accessor_symbol)
            string(FIND "${accessor_disassembly}" "*(u${width} *)" natural_access)
            if(accessor_symbol EQUAL -1 OR natural_access EQUAL -1)
                message(
                    FATAL_ERROR
                        "managed u${width} atomic ${operation} contract is absent from ${OBJECT}"
                )
            endif()
        endforeach()
    endforeach()
endif()
