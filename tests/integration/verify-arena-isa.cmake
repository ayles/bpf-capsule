# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
execute_process(
    COMMAND "${LLVM_OBJDUMP}" -d "${OBJECT}"
    RESULT_VARIABLE status
    OUTPUT_VARIABLE disassembly
    ERROR_VARIABLE error
)
if(NOT status EQUAL 0)
    message(FATAL_ERROR "cannot disassemble ${OBJECT}: ${error}")
endif()

# The fixture contains a volatile signed-byte read from arena memory. Before
# Linux 7.0, PTR_TO_ARENA rejects BPF_MEMSX even though CPU-v4 supports signed
# loads elsewhere. The compiler must retain an unsigned load and extend it
# with ALU operations instead.
if(TARGET_KERNEL VERSION_LESS "7.0")
    string(FIND "${disassembly}" "*(s8 *)" signed_byte_load)
    if(NOT signed_byte_load EQUAL -1)
        message(FATAL_ERROR "pre-7.0 arena object contains a sign-extending arena load")
    endif()
endif()
