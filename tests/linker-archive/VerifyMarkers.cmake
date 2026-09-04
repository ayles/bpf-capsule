# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

file(MAKE_DIRECTORY "${WORK}")

function(expect_failure name expected)
    execute_process(
        COMMAND "${CAPSULE_LD}" --passes=no-op-module --emit-llvm -o "${WORK}/${name}.bc" ${ARGN} "${SOURCE}"
        RESULT_VARIABLE result
        OUTPUT_VARIABLE output
        ERROR_VARIABLE error
    )
    if(NOT result)
        message(FATAL_ERROR "${name} unexpectedly succeeded")
    endif()
    if(NOT "${output}${error}" MATCHES "${expected}")
        message(FATAL_ERROR "${name} failed for the wrong reason:\n${output}${error}")
    endif()
endfunction()

expect_failure(memory-mismatch "runtime memory backend disagrees" --memory=arena)
expect_failure(lock-mismatch "platform allocator lock disagrees" --allocator-lock=atomic)

execute_process(
    COMMAND "${CAPSULE_LD}" --passes=no-op-module --emit-llvm -o "${WORK}/matching.bc" "${SOURCE}"
    RESULT_VARIABLE result
    OUTPUT_VARIABLE output
    ERROR_VARIABLE error
)
if(result)
    message(FATAL_ERROR "matching platform markers failed (${result}):\n${output}${error}")
endif()
