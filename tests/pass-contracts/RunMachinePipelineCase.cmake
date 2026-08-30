# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
# Cross-pass machine contract for the one state MIR cannot serialize: cloned
# blocks retain BasicBlock provenance from their allocation-unit functions
# until final placement restores each dispatch leaf beside its body.

foreach(required LLC PLUGIN LLVM_AS LLVM_DIS BEFORE AFTER WORK)
    if(NOT DEFINED ${required} OR "${${required}}" STREQUAL "")
        message(FATAL_ERROR "RunMachinePipelineCase.cmake needs -D${required}=...")
    endif()
endforeach()

file(REMOVE_RECURSE "${WORK}")
file(MAKE_DIRECTORY "${WORK}")

function(run_checked description)
    execute_process(
        COMMAND ${ARGN}
        RESULT_VARIABLE result
        OUTPUT_VARIABLE output
        ERROR_VARIABLE error
    )
    if(NOT result EQUAL 0)
        message(FATAL_ERROR "${description} failed (${result})\nstdout:\n${output}\nstderr:\n${error}")
    endif()
endfunction()

function(read_normalized path output)
    file(READ "${path}" text)
    string(REGEX REPLACE "  ; ModuleID = '[^\n]*'\n" "" text "${text}")
    string(REGEX REPLACE "^; ModuleID = '[^\n]*'\n" "" text "${text}")
    set(${output} "${text}" PARENT_SCOPE)
endfunction()

# Keep the source module itself canonical, just like direct IR contracts.
run_checked("assembling ${BEFORE}" "${LLVM_AS}" "${BEFORE}" -o "${WORK}/before.bc")
run_checked("printing ${BEFORE}" "${LLVM_DIS}" "${WORK}/before.bc" -o "${WORK}/before.printed.ll")
read_normalized("${BEFORE}" recorded_before)
read_normalized("${WORK}/before.printed.ll" canonical_before)
if(NOT recorded_before STREQUAL canonical_before)
    file(WRITE "${WORK}/before.canonical.ll" "${canonical_before}")
    message(FATAL_ERROR "${BEFORE} is not canonical; canonical form: ${WORK}/before.canonical.ll")
endif()

# The expected final MIR must also be a stable LLVM parser/printer image.
run_checked(
    "canonicalizing ${AFTER}"
    "${LLC}" -mcpu=v4 -run-pass=none -simplify-mir "${AFTER}" -o "${WORK}/after.printed.mir"
)
read_normalized("${AFTER}" recorded_after)
read_normalized("${WORK}/after.printed.mir" canonical_after)
if(NOT recorded_after STREQUAL canonical_after)
    file(WRITE "${WORK}/after.canonical.mir" "${canonical_after}")
    message(FATAL_ERROR "${AFTER} is not canonical; canonical form: ${WORK}/after.canonical.mir")
endif()

# Do not serialize between flattening, stock block placement and finalization:
# cross-function BasicBlock provenance is the input to dispatch-locality repair.
run_checked(
    "running the uninterrupted machine-flatten pipeline"
    "${LLC}" "-load=${PLUGIN}" -mcpu=v4 -bpf-unified-spill-pipeline
    -stop-after=bpf-machine-flatten-finalize -simplify-mir "${BEFORE}" -o "${WORK}/actual.raw.mir"
)
run_checked(
    "canonicalizing actual machine output"
    "${LLC}" -mcpu=v4 -run-pass=none -simplify-mir "${WORK}/actual.raw.mir" -o "${WORK}/actual.printed.mir"
)
read_normalized("${WORK}/actual.printed.mir" actual)
file(WRITE "${WORK}/actual.mir" "${actual}")

if(NOT actual STREQUAL canonical_after)
    execute_process(
        COMMAND diff -u "${AFTER}" "${WORK}/actual.mir"
        OUTPUT_VARIABLE difference
        ERROR_VARIABLE diff_error
    )
    message(FATAL_ERROR "machine pipeline output differs from ${AFTER}\n${difference}${diff_error}\nactual: ${WORK}/actual.mir")
endif()

# The MIR printer does not serialize MachineBasicBlock's force-label bit.
# Complete object emission is therefore part of this contract: in particular,
# a post-placement v4 jump-table target must still acquire an emitted label.
run_checked(
    "emitting an object from the uninterrupted machine-flatten pipeline"
    "${LLC}" "-load=${PLUGIN}" -mcpu=v4 -bpf-unified-spill-pipeline
    -filetype=obj "${BEFORE}" -o "${WORK}/output.o"
)
