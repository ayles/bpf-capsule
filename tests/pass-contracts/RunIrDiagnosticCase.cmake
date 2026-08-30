# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
# Contract for a pass that must reject malformed or unsupported input.  The IR
# is canonicalized exactly like a before/after case; every non-empty line in
# the checked-in errors file must occur in the diagnostic.

foreach(required BPF_CAPSULE_LD LLVM_AS LLVM_DIS PIPELINE BEFORE ERRORS WORK)
    if(NOT DEFINED ${required} OR "${${required}}" STREQUAL "")
        message(FATAL_ERROR "RunIrDiagnosticCase.cmake needs -D${required}=...")
    endif()
endforeach()

file(REMOVE_RECURSE "${WORK}")
file(MAKE_DIRECTORY "${WORK}")

execute_process(COMMAND "${LLVM_AS}" "${BEFORE}" -o "${WORK}/before.bc" RESULT_VARIABLE result ERROR_VARIABLE error)
if(NOT result EQUAL 0)
    message(FATAL_ERROR "cannot assemble ${BEFORE}: ${error}")
endif()
execute_process(COMMAND "${LLVM_DIS}" "${WORK}/before.bc" -o "${WORK}/before.printed.ll" RESULT_VARIABLE result ERROR_VARIABLE error)
if(NOT result EQUAL 0)
    message(FATAL_ERROR "cannot print ${BEFORE}: ${error}")
endif()
file(READ "${WORK}/before.printed.ll" canonical)
string(REGEX REPLACE "^; ModuleID = '[^\n]*'\n" "" canonical "${canonical}")
file(READ "${BEFORE}" recorded)
string(REGEX REPLACE "^; ModuleID = '[^\n]*'\n" "" recorded "${recorded}")
if(NOT recorded STREQUAL canonical)
    file(WRITE "${WORK}/before.canonical.ll" "${canonical}")
    message(FATAL_ERROR "${BEFORE} is not canonical; canonical form: ${WORK}/before.canonical.ll")
endif()

set(command "${BPF_CAPSULE_LD}" "--passes=${PIPELINE}" --emit-llvm -o "${WORK}/unexpected.bc")
if(DEFINED EXTRA_ARG AND NOT "${EXTRA_ARG}" STREQUAL "")
    string(REPLACE "|" ";" extra_args "${EXTRA_ARG}")
    list(APPEND command ${extra_args})
endif()
list(APPEND command "${BEFORE}")
execute_process(
    COMMAND ${command}
    RESULT_VARIABLE result
    OUTPUT_VARIABLE output
    ERROR_VARIABLE error
)
if(result EQUAL 0)
    message(FATAL_ERROR "${PIPELINE} unexpectedly accepted ${BEFORE}")
endif()

file(STRINGS "${ERRORS}" required_errors)
foreach(required IN LISTS required_errors)
    string(STRIP "${required}" required)
    if(required STREQUAL "" OR required MATCHES "^#")
        continue()
    endif()
    string(FIND "${error}" "${required}" position)
    if(position EQUAL -1)
        message(FATAL_ERROR
            "diagnostic does not contain required text:\n  ${required}\nstdout:\n${output}\nstderr:\n${error}")
    endif()
endforeach()
