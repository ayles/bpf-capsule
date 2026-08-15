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
    message(FATAL_ERROR "large physical fixture still uses bpf_spill_scratch")
endif()
if(NOT relocations MATCHES "bpf_call_stack")
    message(FATAL_ERROR "large physical fixture did not use its unified stack")
endif()

execute_process(
    COMMAND "${LLVM_OBJDUMP}" --disassemble --no-show-raw-insn "${OBJECT}"
    RESULT_VARIABLE result
    OUTPUT_VARIABLE disassembly
    ERROR_VARIABLE error
)
if(NOT result EQUAL 0)
    message(FATAL_ERROR "cannot disassemble ${OBJECT}: ${error}")
endif()
if(NOT disassembly MATCHES "\\+ 0x[234567][0-9a-f][0-9a-f][0-9a-f]\\)")
    message(FATAL_ERROR "large physical fixture did not relocate more than 8 KiB")
endif()
# BPF memory instructions carry only a signed 16-bit offset. This fixture is
# larger than 32 KiB, so the upper portion must appear as 32-bit ADD-immediate
# pointer materialization followed by an encodable memory access.
if(NOT disassembly MATCHES "r[0-9]+ \\+= 0x[89abcdef][0-9a-f][0-9a-f][0-9a-f]")
    message(FATAL_ERROR "large physical fixture did not materialize a spill offset above 32 KiB")
endif()
# The encoded exit word does not fit one 32-bit store immediate: the collision
# guard publishes the CAPSULE_EXITED tag (3) in the low half and the signed
# CAPSULE_ERROR_STACK_OVERFLOW code (-7) in the high half (little-endian).
if(NOT disassembly MATCHES "\\+ 0x0\\) = 0x3")
    message(FATAL_ERROR "large physical fixture has no unified-stack collision exit tag store")
endif()
if(NOT disassembly MATCHES "\\+ 0x4\\) = -0x7")
    message(FATAL_ERROR "large physical fixture has no unified-stack collision overflow-code store")
endif()
