# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
# Test the installed archive, including implicit extraction for IR arithmetic.
# A multiply must stay call-free through both pre- and post-O2 lowering.
file(MAKE_DIRECTORY "${WORK}")
execute_process(
    COMMAND
        "${BPF_CAPSULE_LD}" "--passes=bpf-expand-i128,function(bpf-inline-policy),default<O2>,bpf-expand-i128"
        --emit-llvm "${SOURCE}" "${BUILTINS}" -o "${WORK}/multiply.bc"
    COMMAND_ERROR_IS_FATAL ANY
)
execute_process(COMMAND "${LLVM_DIS}" "${WORK}/multiply.bc" -o "${WORK}/multiply.ll" COMMAND_ERROR_IS_FATAL ANY)
file(READ "${WORK}/multiply.ll" ir)
if(ir MATCHES "call[^\n]*@__(multi3|mulddi3)" OR ir MATCHES "mul i128")
    message(FATAL_ERROR "Wide multiplication still needs a call: ${WORK}/multiply.ll")
endif()
