# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
execute_process(
    COMMAND "${LLVM_OBJDUMP}" -d --disassemble-symbols=bpf_heap_load64,bpf_heap_store64 "${OBJECT}"
    RESULT_VARIABLE result
    OUTPUT_VARIABLE disassembly
    ERROR_VARIABLE error
)
if(NOT result EQUAL 0)
    message(FATAL_ERROR "cannot disassemble ${OBJECT}: ${error}")
endif()

# Dynamic Capsule addresses are not naturally aligned, but a BPF word access
# itself supports them. Losing the compiler's natural-width codegen contract
# made LLVM scalarize every u64 operation into eight byte operations and cost
# interpreters 20--30%. Keep this check on the emitted ISA, where the bug lived.
string(FIND "${disassembly}" "<bpf_heap_load64>" load_symbol)
string(FIND "${disassembly}" "<bpf_heap_store64>" store_symbol)
string(FIND "${disassembly}" "*(u64 *)" wide_access)
string(FIND "${disassembly}" "*(u8 *)" byte_access)
if(load_symbol EQUAL -1
   OR store_symbol EQUAL -1
   OR wide_access EQUAL -1
)
    message(FATAL_ERROR "fixed-memory u64 accessors are absent from ${OBJECT}")
endif()
if(NOT byte_access EQUAL -1)
    message(FATAL_ERROR "64-bit fixed-memory accessor was scalarized into byte operations")
endif()
