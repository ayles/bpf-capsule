# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

execute_process(
    COMMAND "${CAPSULE_CC}" -E "${SOURCE}" -o "${OUTPUT}"
    RESULT_VARIABLE result
    ERROR_VARIABLE error
)
if(NOT result)
    message(FATAL_ERROR "guest compiler found a host-only glibc header")
endif()
if(NOT error MATCHES "gnu/libc-version.h.*file not found")
    message(FATAL_ERROR "unexpected include-isolation diagnostic:\n${error}")
endif()
