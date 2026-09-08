# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
# Every spelling must configure the actual managed stack, including options
# inside LLVM response files that an argv pre-scan would not see.
file(MAKE_DIRECTORY "${WORK}")
function(check_stack name bytes)
    execute_process(
        COMMAND "${BPF_CAPSULE_LD}" --emit-llvm ${ARGN} "${BEFORE}" -o "${WORK}/${name}.bc"
        COMMAND_ERROR_IS_FATAL ANY
    )
    execute_process(COMMAND "${LLVM_DIS}" "${WORK}/${name}.bc" -o "${WORK}/${name}.ll" COMMAND_ERROR_IS_FATAL ANY)
    file(READ "${WORK}/${name}.ll" ir)
    if(NOT ir MATCHES "@bpf_call_stack = internal global \\[${bytes} x i8\\]")
        message(FATAL_ERROR "${name}: expected a ${bytes}-byte managed stack")
    endif()
endfunction()
check_stack(default 262144 --passes=bpf-stackify)
check_stack(equals 131072 --passes=bpf-stackify --fiber-stack=131072)
check_stack(separate 131072 --passes=bpf-stackify --fiber-stack 131072)
check_stack(single_dash 131072 -passes=bpf-stackify -fiber-stack=131072)
check_stack(maximum 2097152 --passes=bpf-stackify --fiber-stack=2097152)
file(WRITE "${WORK}/options.rsp" "--passes=bpf-stackify\n--fiber-stack=524288\n")
check_stack(response 524288 "@${WORK}/options.rsp")

foreach(
    bytes
    0
    3
    4194304
    4294967295
    invalid
)
    execute_process(
        COMMAND
            "${BPF_CAPSULE_LD}" --passes=bpf-stackify --emit-llvm "--fiber-stack=${bytes}" "${BEFORE}" -o
            "${WORK}/invalid.bc"
        RESULT_VARIABLE result
        ERROR_VARIABLE error
    )
    if(result STREQUAL "0" OR NOT error MATCHES "(fiber.stack|bpf-stack-size)")
        message(FATAL_ERROR "Invalid stack size ${bytes} was not diagnosed: ${error}")
    endif()
endforeach()
