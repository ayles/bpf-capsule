# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
# Run one IR pass and compare complete canonical modules.  Canonicalization is
# deliberately narrow: LLVM's parser/printer owns syntax, numbering, attribute
# grouping and metadata ordering; only the bitcode-container-specific ModuleID
# line is discarded.

foreach(
    required
    BPF_CAPSULE_LD
    LLVM_AS
    LLVM_DIS
    PIPELINE
    BEFORE
    AFTER
    WORK
)
    if(NOT DEFINED ${required} OR "${${required}}" STREQUAL "")
        message(FATAL_ERROR "RunIrPassCase.cmake needs -D${required}=...")
    endif()
endforeach()

file(REMOVE_RECURSE "${WORK}")
file(MAKE_DIRECTORY "${WORK}")

function(run_checked description)
    execute_process(COMMAND ${ARGN} RESULT_VARIABLE result OUTPUT_VARIABLE output ERROR_VARIABLE error)
    if(NOT result EQUAL 0)
        message(FATAL_ERROR "${description} failed (${result})\nstdout:\n${output}\nstderr:\n${error}")
    endif()
endfunction()

function(canonicalize input stem output_var)
    set(bitcode "${WORK}/${stem}.bc")
    set(printed "${WORK}/${stem}.printed.ll")
    run_checked("assembling ${input}" "${LLVM_AS}" "${input}" -o "${bitcode}")
    run_checked("printing ${input}" "${LLVM_DIS}" "${bitcode}" -o "${printed}")
    file(READ "${printed}" text)
    string(REGEX REPLACE "^; ModuleID = '[^\n]*'\n" "" text "${text}")
    set("${output_var}" "${text}" PARENT_SCOPE)
endfunction()

# The before image is itself a contract artifact: reject hand-written syntax
# whose canonical LLVM spelling differs from what reviewers see in the file.
canonicalize("${BEFORE}" before before_canonical)
file(READ "${BEFORE}" before_recorded)
string(REGEX REPLACE "^; ModuleID = '[^\n]*'\n" "" before_recorded "${before_recorded}")
if(NOT before_recorded STREQUAL before_canonical)
    file(WRITE "${WORK}/before.canonical.ll" "${before_canonical}")
    message(FATAL_ERROR "${BEFORE} is not canonical; canonical form: ${WORK}/before.canonical.ll")
endif()

set(actual_bc "${WORK}/actual.bc")
set(command
    "${BPF_CAPSULE_LD}"
    "--passes=${PIPELINE}"
    --emit-llvm
    -o
    "${actual_bc}"
)
if(DEFINED EXTRA_ARG AND NOT "${EXTRA_ARG}" STREQUAL "")
    string(REPLACE "|" ";" extra_args "${EXTRA_ARG}")
    list(APPEND command ${extra_args})
endif()
list(APPEND command "${BEFORE}")
run_checked(
    "running ${PIPELINE}"
    ${command}
)
run_checked("printing actual result" "${LLVM_DIS}" "${actual_bc}" -o "${WORK}/actual.printed.ll")
file(READ "${WORK}/actual.printed.ll" actual)
string(REGEX REPLACE "^; ModuleID = '[^\n]*'\n" "" actual "${actual}")

canonicalize("${AFTER}" expected expected)
file(READ "${AFTER}" after_recorded)
string(REGEX REPLACE "^; ModuleID = '[^\n]*'\n" "" after_recorded "${after_recorded}")
if(NOT after_recorded STREQUAL expected)
    file(WRITE "${WORK}/after.canonical.ll" "${expected}")
    message(FATAL_ERROR "${AFTER} is not canonical; canonical form: ${WORK}/after.canonical.ll")
endif()

if(NOT actual STREQUAL expected)
    file(WRITE "${WORK}/actual.ll" "${actual}")
    file(WRITE "${WORK}/expected.ll" "${expected}")
    execute_process(
        COMMAND diff -u "${WORK}/expected.ll" "${WORK}/actual.ll"
        OUTPUT_VARIABLE difference
        ERROR_VARIABLE diff_error
    )
    message(FATAL_ERROR "pass output differs from ${AFTER}\n${difference}${diff_error}\nactual: ${WORK}/actual.ll")
endif()
