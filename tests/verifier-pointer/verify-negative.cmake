# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
foreach(PROFILE 5.15 6.9)
    foreach(CASE unsupported-call unsupported-sectioned-global-call unsupported-loop-boundary
                 unsupported-loop-chunk
    )
        execute_process(
            COMMAND
                "${OPT}" "-load-pass-plugin=${PLUGIN}" "-bpf-target=${PROFILE}" -bpf-inline-max=0
                -bpf-stackify-phase=2 --passes=bpf-stackify "${SOURCE_DIR}/${CASE}.ll"
                -disable-output
            RESULT_VARIABLE STATUS
            OUTPUT_VARIABLE OUTPUT
            ERROR_VARIABLE ERROR
        )
        set(LOG "${OUTPUT}${ERROR}")
        if(NOT STATUS EQUAL 1)
            message(FATAL_ERROR "${CASE} on Linux ${PROFILE} exited ${STATUS}, expected 1:\n${LOG}")
        endif()
        if(CASE STREQUAL "unsupported-call")
            set(EXPECTED "is live across a Capsule suspension point")
        elseif(CASE STREQUAL "unsupported-sectioned-global-call")
            set(EXPECTED "is passed through a Capsule suspension point")
        elseif(CASE STREQUAL "unsupported-loop-boundary")
            set(EXPECTED "is live across a suspendable loop boundary")
        else()
            set(EXPECTED "is live across a suspendable loop chunk")
        endif()
        string(FIND "${LOG}" "${EXPECTED}" FOUND)
        if(FOUND EQUAL -1)
            message(FATAL_ERROR "${CASE} on Linux ${PROFILE} missed '${EXPECTED}':\n${LOG}")
        endif()
        string(FIND "${LOG}" "PLEASE submit a bug report" CRASH_BANNER)
        string(FIND "${LOG}" "Stack dump:" STACK_DUMP)
        if(NOT CRASH_BANNER EQUAL -1 OR NOT STACK_DUMP EQUAL -1)
            message(
                FATAL_ERROR
                    "${CASE} on Linux ${PROFILE} crashed instead of failing cleanly:\n${LOG}"
            )
        endif()
    endforeach()
endforeach()

message(STATUS "VERIFIER-POINTER-LIFETIME-PASS")
