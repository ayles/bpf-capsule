# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
set(CASES
    unsupported-dynamic-alloca
    unsupported-borrowed-context
    unsupported-variadic
    unsupported-variadic-extern
    unsupported-variadic-invoke
    unsupported-wide-varargs
    unsupported-wide-float
    unsupported-narrow-float
    unsupported-vector-float
    unsupported-vector-float-conversion
    unsupported-wide-float-conversion
    unsupported-wide-float-conversion-result
    unsupported-capsule-call
)

foreach(PROFILE 5.15 6.9)
    foreach(CASE IN LISTS CASES)
        if(CASE STREQUAL "unsupported-wide-varargs"
           OR CASE STREQUAL "unsupported-variadic-invoke"
           OR CASE STREQUAL "unsupported-variadic-extern"
        )
            set(PIPELINE bpf-expand-varargs)
        elseif(CASE MATCHES "unsupported-(wide|narrow|vector)-float")
            set(PIPELINE bpf-soft-float)
        elseif(CASE STREQUAL "unsupported-capsule-call")
            set(PIPELINE bpf-partition)
        else()
            set(PIPELINE bpf-stackify)
        endif()
        execute_process(
            COMMAND "${OPT}" "-load-pass-plugin=${PLUGIN}" "-bpf-target=${PROFILE}"
                    "--passes=${PIPELINE}" "${SOURCE_DIR}/${CASE}.ll" -disable-output
            RESULT_VARIABLE STATUS
            OUTPUT_VARIABLE OUTPUT
            ERROR_VARIABLE ERROR
        )
        set(LOG "${OUTPUT}${ERROR}")
        if(NOT STATUS EQUAL 1)
            message(FATAL_ERROR "${CASE} on Linux ${PROFILE} exited ${STATUS}, expected 1:\n${LOG}")
        endif()
        if(CASE STREQUAL "unsupported-dynamic-alloca")
            set(EXPECTED "dynamic alloca survived VLA lowering")
        elseif(CASE STREQUAL "unsupported-borrowed-context")
            set(EXPECTED "needs debug/BTF type information")
        elseif(CASE STREQUAL "unsupported-variadic")
            set(EXPECTED "variadic function survived ABI expansion")
        elseif(CASE STREQUAL "unsupported-variadic-invoke")
            set(EXPECTED "invoke of variadic variadic_callee is unsupported")
        elseif(CASE STREQUAL "unsupported-variadic-extern")
            set(EXPECTED "call to declared-only variadic external external_log is unsupported")
        elseif(CASE STREQUAL "unsupported-wide-varargs")
            set(EXPECTED "wider than the 8-byte BPF variadic slot")
        elseif(CASE STREQUAL "unsupported-wide-float")
            set(EXPECTED "floating-point values wider than 64 bits are unsupported")
        elseif(CASE STREQUAL "unsupported-narrow-float")
            set(EXPECTED "only float and double scalar values are supported")
        elseif(CASE MATCHES "^unsupported-vector-float")
            set(EXPECTED "floating-point vectors are unsupported")
        elseif(CASE MATCHES "^unsupported-wide-float-conversion")
            set(EXPECTED
                "conversions between floating point and integers wider than 64 bits are unsupported"
            )
        else()
            set(EXPECTED "capsule return storage does not match")
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

# The exit marker has an internal ABI and must remain a direct call from the
# managed domain. Diagnose malformed declarations and escaping addresses at
# the partition boundary rather than crashing or producing corrupt control IR.
foreach(CASE malformed-exit-marker escaping-exit-marker)
    foreach(PROFILE 5.15 6.9)
        execute_process(
            COMMAND "${OPT}" "-load-pass-plugin=${PLUGIN}" "-bpf-target=${PROFILE}"
                    --passes=bpf-partition "${SOURCE_DIR}/${CASE}.ll" -disable-output
            RESULT_VARIABLE STATUS
            OUTPUT_VARIABLE OUTPUT
            ERROR_VARIABLE ERROR
        )
        set(LOG "${OUTPUT}${ERROR}")
        if(NOT STATUS EQUAL 1)
            message(FATAL_ERROR "${CASE} on Linux ${PROFILE} exited ${STATUS}, expected 1:\n${LOG}")
        endif()
        if(CASE STREQUAL "malformed-exit-marker")
            set(EXPECTED "malformed __bpf_capsule_exit marker")
        else()
            set(EXPECTED "__bpf_capsule_exit must be called directly from managed code")
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

# The pack is byte-addressed, but every slot may contain an i64. Keep the
# entry-block allocation explicitly aligned rather than relying on a later
# backend to repair an under-aligned IR store.
foreach(PROFILE 5.15 6.9)
    execute_process(
        COMMAND
            "${OPT}" "-load-pass-plugin=${PLUGIN}" "-bpf-target=${PROFILE}"
            --passes=bpf-expand-varargs,verify "${SOURCE_DIR}/supported-varargs-align.ll" -S -o -
        RESULT_VARIABLE STATUS
        OUTPUT_VARIABLE OUTPUT
        ERROR_VARIABLE ERROR
    )
    if(NOT STATUS EQUAL 0)
        message(FATAL_ERROR "supported varargs on Linux ${PROFILE} failed:\n${OUTPUT}${ERROR}")
    endif()
    string(FIND "${OUTPUT}" "%vararg.buffer = alloca [8 x i8], align 8" ALIGNED_PACK)
    if(ALIGNED_PACK EQUAL -1)
        message(
            FATAL_ERROR
                "supported varargs on Linux ${PROFILE} lost 8-byte pack alignment:\n${OUTPUT}"
        )
    endif()
endforeach()

# Named aggregate bodies containing float fields are rewritten structurally.
# Instructions which cache a selected element type must follow that rewrite.
foreach(PROFILE 5.15 6.9)
    execute_process(
        COMMAND
            "${OPT}" "-load-pass-plugin=${PLUGIN}" "-bpf-target=${PROFILE}"
            --passes=bpf-soft-float,verify "${SOURCE_DIR}/supported-soft-float-aggregate.ll"
            -disable-output
        RESULT_VARIABLE STATUS
        OUTPUT_VARIABLE OUTPUT
        ERROR_VARIABLE ERROR
    )
    if(NOT STATUS EQUAL 0)
        message(
            FATAL_ERROR
                "supported soft-float aggregate on Linux ${PROFILE} failed:\n${OUTPUT}${ERROR}"
        )
    endif()
endforeach()

# A raw exit-marker call is permitted to have ordinary CFG after it. The
# lowering returns at the marker and must remove the erased successor edges
# from their PHIs, leaving a valid module.
foreach(PROFILE 5.15 6.9)
    execute_process(
        COMMAND "${OPT}" "-load-pass-plugin=${PLUGIN}" "-bpf-target=${PROFILE}"
                --passes=bpf-partition,verify "${SOURCE_DIR}/supported-throw-cfg.ll" -S -o -
        RESULT_VARIABLE STATUS
        OUTPUT_VARIABLE OUTPUT
        ERROR_VARIABLE ERROR
    )
    if(NOT STATUS EQUAL 0)
        message(FATAL_ERROR "supported exit CFG on Linux ${PROFILE} failed:\n${OUTPUT}${ERROR}")
    endif()
    string(REGEX MATCH "define i32 @throw_through_lifetime[^}]+" LIFETIME_WRAPPER "${OUTPUT}")
    if(NOT LIFETIME_WRAPPER MATCHES "ret i32" OR LIFETIME_WRAPPER MATCHES "unreachable")
        message(
            FATAL_ERROR
                "exit wrapper lifetime marker was not reopened on Linux ${PROFILE}:\n${LIFETIME_WRAPPER}"
        )
    endif()
endforeach()

message(STATUS "COMPILER-ERROR-CONTRACT-PASS")
