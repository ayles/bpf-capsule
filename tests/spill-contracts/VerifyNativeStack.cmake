# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
foreach(required LLC PLUGIN LLVM_READELF TARGET_KERNEL SOURCE_DIR WORK)
    if(NOT DEFINED ${required} OR "${${required}}" STREQUAL "")
        message(FATAL_ERROR "VerifyNativeStack.cmake needs -D${required}=...")
    endif()
endforeach()

file(REMOVE_RECURSE "${WORK}")
file(MAKE_DIRECTORY "${WORK}")
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
    -bpf-unified-spill-pipeline -bpf-unified-spill-limit=0
    -bpf-stack-size=262144 -verify-machineinstrs -filetype=obj
    -o "${WORK}/native-zero.o" "${SOURCE_DIR}/native-zero.ll"
    RESULT_VARIABLE result OUTPUT_VARIABLE output ERROR_VARIABLE error)
if(NOT result EQUAL 0)
    message(FATAL_ERROR "zero-budget native fixture failed: ${output}${error}")
endif()
execute_process(COMMAND "${LLVM_READELF}" --relocations "${WORK}/native-zero.o"
    RESULT_VARIABLE result OUTPUT_VARIABLE relocations ERROR_VARIABLE error)
if(NOT result EQUAL 0)
    message(FATAL_ERROR "cannot inspect native-zero.o: ${error}")
endif()
if(relocations MATCHES "bpf_spill_scratch" OR relocations MATCHES "bpf_call_stack")
    message(FATAL_ERROR "native entry without a leased fiber was relocated into fiber storage")
endif()

execute_process(COMMAND "${LLC}" -O2 -mcpu=${cpu} "-load=${PLUGIN}"
    -bpf-unified-spill-pipeline "-bpf-unified-spill-limit=${native_limit}"
    -bpf-stack-size=262144 -verify-machineinstrs -filetype=obj
    -o "${WORK}/oversized-native.o" "${SOURCE_DIR}/oversized-native.ll"
    RESULT_VARIABLE result OUTPUT_VARIABLE output ERROR_VARIABLE error)
set(log "${output}${error}")
if(result EQUAL 0)
    message(FATAL_ERROR "oversized native frame compiled successfully")
endif()
if(NOT log MATCHES "native function oversized_native exceeds the 512-byte BPF stack" AND
   NOT log MATCHES "native BPF call path uses [0-9]+ stack bytes; kernel limit is 512: oversized_native")
    message(FATAL_ERROR "oversized native frame missed its diagnostic: ${log}")
endif()
if(log MATCHES "PLEASE submit a bug report" OR log MATCHES "Stack dump:")
    message(FATAL_ERROR "oversized native frame crashed instead of failing cleanly: ${log}")
endif()
