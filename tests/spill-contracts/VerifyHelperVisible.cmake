# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
foreach(required LLC PLUGIN LLVM_READELF LLVM_OBJDUMP TARGET_KERNEL GENERATOR WORK)
    if(NOT DEFINED ${required} OR "${${required}}" STREQUAL "")
        message(FATAL_ERROR "VerifyHelperVisible.cmake needs -D${required}=...")
    endif()
endforeach()

file(REMOVE_RECURSE "${WORK}")
file(MAKE_DIRECTORY "${WORK}")
set(source "${WORK}/helper-visible.ll")
set(object "${WORK}/helper-visible.o")
execute_process(COMMAND "${CMAKE_COMMAND}" -DOUTPUT=${source} -DWORD_COUNT=48 -P "${GENERATOR}"
    RESULT_VARIABLE result OUTPUT_VARIABLE output ERROR_VARIABLE error)
if(NOT result EQUAL 0)
    message(FATAL_ERROR "cannot generate helper-visible fixture: ${output}${error}")
endif()

if(TARGET_KERNEL VERSION_GREATER_EQUAL "6.6")
    set(cpu v4)
else()
    set(cpu v3)
endif()
if(TARGET_KERNEL VERSION_GREATER_EQUAL "6.9")
    set(native_limit 352)
else()
    set(native_limit 320)
endif()
execute_process(COMMAND "${LLC}" -O2 -mcpu=${cpu} "-load=${PLUGIN}"
    -bpf-unified-spill-pipeline "-bpf-unified-spill-limit=${native_limit}"
    -bpf-stack-size=262144 -verify-machineinstrs -filetype=obj
    -o "${object}" "${source}"
    RESULT_VARIABLE result OUTPUT_VARIABLE output ERROR_VARIABLE error)
if(NOT result EQUAL 0)
    message(FATAL_ERROR "helper-visible fixture failed: ${output}${error}")
endif()

execute_process(COMMAND "${LLVM_READELF}" --relocations "${object}"
    RESULT_VARIABLE result OUTPUT_VARIABLE relocations ERROR_VARIABLE error)
if(NOT result EQUAL 0)
    message(FATAL_ERROR "cannot inspect helper-visible relocations: ${error}")
endif()
if(NOT relocations MATCHES "bpf_call_stack")
    message(FATAL_ERROR "unrelated scalar spills did not move to unified fiber memory")
endif()

execute_process(COMMAND "${LLVM_OBJDUMP}" --disassemble --no-show-raw-insn "${object}"
    RESULT_VARIABLE result OUTPUT_VARIABLE disassembly ERROR_VARIABLE error)
if(NOT result EQUAL 0)
    message(FATAL_ERROR "cannot disassemble helper-visible object: ${error}")
endif()
# The helper receives r10-296 and size 288. Its complete range is therefore
# r10-296 through r10-9. The single byte initialization at the first address
# and the guard at r10-8 are intentional; another native-stack access in the
# interior would prove that spill packing overlapped helper-visible memory.
if(NOT disassembly MATCHES "r1 \\+= -0x128" OR
   NOT disassembly MATCHES "w2 = 0x120" OR
   NOT disassembly MATCHES "call 0x71")
    message(FATAL_ERROR "helper buffer pointer/extent did not survive code generation:\n${disassembly}")
endif()
string(REGEX MATCHALL "r10 - 0x[0-9a-f]+" native_accesses "${disassembly}")
set(has_below_buffer FALSE)
foreach(access IN LISTS native_accesses)
    string(REGEX REPLACE ".*0x" "" offset_hex "${access}")
    math(EXPR offset "0x${offset_hex}")
    if(offset GREATER 8 AND offset LESS 296)
        message(FATAL_ERROR "native spill overlaps the helper-visible buffer at ${access}")
    endif()
    if(offset GREATER 296)
        set(has_below_buffer TRUE)
    endif()
endforeach()
if(NOT has_below_buffer)
    message(FATAL_ERROR "fixture did not retain any native state below the helper buffer")
endif()
