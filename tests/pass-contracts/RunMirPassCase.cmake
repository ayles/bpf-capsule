# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
# Exact post-selection contract. llc owns both MIR parsing and canonical
# printing; -simplify-mir removes fields whose default value carries no
# semantic information. Only the input-path-derived ModuleID is ignored.

foreach(required LLC PLUGIN PASS BEFORE AFTER WORK)
    if(NOT DEFINED ${required} OR "${${required}}" STREQUAL "")
        message(FATAL_ERROR "RunMirPassCase.cmake needs -D${required}=...")
    endif()
endforeach()

file(REMOVE_RECURSE "${WORK}")
file(MAKE_DIRECTORY "${WORK}")

function(read_normalized path output)
    file(READ "${path}" text)
    string(REGEX REPLACE "  ; ModuleID = '[^\n]*'\n" "" text "${text}")
    set(${output} "${text}" PARENT_SCOPE)
endfunction()

function(print_canonical input output)
    execute_process(
        COMMAND "${LLC}" "-load=${PLUGIN}" -run-pass=none -simplify-mir "${input}" -o "${output}"
        RESULT_VARIABLE result
        ERROR_VARIABLE error
    )
    if(NOT result EQUAL 0)
        message(FATAL_ERROR "cannot canonicalize MIR ${input}: ${error}")
    endif()
endfunction()

print_canonical("${BEFORE}" "${WORK}/before.printed.mir")
read_normalized("${BEFORE}" recorded_before)
read_normalized("${WORK}/before.printed.mir" canonical_before)
if(NOT recorded_before STREQUAL canonical_before)
    file(WRITE "${WORK}/before.canonical.mir" "${canonical_before}")
    message(FATAL_ERROR "${BEFORE} is not canonical; canonical form: ${WORK}/before.canonical.mir")
endif()

print_canonical("${AFTER}" "${WORK}/after.printed.mir")
read_normalized("${AFTER}" recorded_after)
read_normalized("${WORK}/after.printed.mir" canonical_after)
if(NOT recorded_after STREQUAL canonical_after)
    file(WRITE "${WORK}/after.canonical.mir" "${canonical_after}")
    message(FATAL_ERROR "${AFTER} is not canonical; canonical form: ${WORK}/after.canonical.mir")
endif()

set(command "${LLC}" "-load=${PLUGIN}" "-run-pass=${PASS}" -simplify-mir)
if(DEFINED EXTRA_ARG AND NOT "${EXTRA_ARG}" STREQUAL "")
    string(REPLACE "|" ";" extra_args "${EXTRA_ARG}")
    list(APPEND command ${extra_args})
endif()
list(APPEND command "${BEFORE}" -o "${WORK}/actual.raw.mir")
execute_process(COMMAND ${command} RESULT_VARIABLE result ERROR_VARIABLE error)
if(NOT result EQUAL 0)
    message(FATAL_ERROR "${PASS} failed on ${BEFORE}: ${error}")
endif()
# A machine pass can append blocks with allocator IDs that are intentionally
# not layout-ordered. Reparse once so the checked contract uses stable block
# numbering just like its checked-in expectation.
print_canonical("${WORK}/actual.raw.mir" "${WORK}/actual.printed.mir")
read_normalized("${WORK}/actual.printed.mir" actual)
file(WRITE "${WORK}/actual.mir" "${actual}")

if(NOT actual STREQUAL canonical_after)
    execute_process(
        COMMAND diff -u "${AFTER}" "${WORK}/actual.mir"
        OUTPUT_VARIABLE difference
        ERROR_VARIABLE diff_error
    )
    message(FATAL_ERROR "MIR pass output differs from ${AFTER}\n${difference}${diff_error}\nactual: ${WORK}/actual.mir")
endif()
