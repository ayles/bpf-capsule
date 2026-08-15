# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
foreach(PROFILE 5.15 6.9)
    execute_process(
        COMMAND "${OPT}" "-load-pass-plugin=${PLUGIN}" "-bpf-target=${PROFILE}"
                -bpf-stackify-phase=1 --passes=bpf-partition,bpf-stackify "${INPUT}" -disable-output
        RESULT_VARIABLE STATUS
        OUTPUT_VARIABLE OUTPUT
        ERROR_VARIABLE ERROR
    )
    set(LOG "${OUTPUT}${ERROR}")
    if(NOT STATUS EQUAL 1)
        message(
            FATAL_ERROR
                "scalar/context contract on Linux ${PROFILE} exited ${STATUS}, expected 1:\n${LOG}"
        )
    endif()
    set(EXPECTED "has a direct call path to context-dependent function")
    string(FIND "${LOG}" "${EXPECTED}" FOUND)
    if(FOUND EQUAL -1)
        message(
            FATAL_ERROR "scalar/context contract on Linux ${PROFILE} missed '${EXPECTED}':\n${LOG}"
        )
    endif()
    string(FIND "${LOG}" "PLEASE submit a bug report" CRASH_BANNER)
    string(FIND "${LOG}" "Stack dump:" STACK_DUMP)
    if(NOT CRASH_BANNER EQUAL -1 OR NOT STACK_DUMP EQUAL -1)
        message(
            FATAL_ERROR
                "scalar/context contract on Linux ${PROFILE} crashed instead of failing cleanly:\n${LOG}"
        )
    endif()
endforeach()

message(STATUS "SCALAR-CONTEXT-CONTRACT-PASS")
