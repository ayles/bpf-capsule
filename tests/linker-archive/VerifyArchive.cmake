# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

file(REMOVE_RECURSE "${WORK}")
file(MAKE_DIRECTORY "${WORK}")

foreach(
    member
    IN
    ITEMS main fp-main mem-main foo bundle optional unused bar data sqrt fabs memcpy memmove memset
)
    execute_process(
        COMMAND "${LLVM_AS}" "${SOURCE_DIR}/${member}.ll" -o "${WORK}/${member}.bc"
        RESULT_VARIABLE result
        ERROR_VARIABLE error
    )
    if(result)
        message(FATAL_ERROR "llvm-as failed for ${member}: ${error}")
    endif()
endforeach()

execute_process(
    COMMAND
        "${LLVM_AR}" rcs "${WORK}/libarchive-primary.a" "${WORK}/foo.bc" "${WORK}/bundle.bc" "${WORK}/optional.bc"
        "${WORK}/unused.bc" "${WORK}/sqrt.bc" "${WORK}/fabs.bc" "${WORK}/memcpy.bc" "${WORK}/memmove.bc"
        "${WORK}/memset.bc"
    RESULT_VARIABLE result
    ERROR_VARIABLE error
)
if(result)
    message(FATAL_ERROR "llvm-ar failed: ${error}")
endif()

execute_process(
    COMMAND "${LLVM_AR}" rcs "${WORK}/libarchive-dependencies.a" "${WORK}/bar.bc" "${WORK}/data.bc"
    RESULT_VARIABLE result
    ERROR_VARIABLE error
)
if(result)
    message(FATAL_ERROR "llvm-ar failed: ${error}")
endif()

execute_process(
    COMMAND
        "${CAPSULE_LD}" --passes=no-op-module --emit-llvm -o "${WORK}/linked.bc" "${WORK}/main.bc" "${WORK}/fp-main.bc"
        "${WORK}/mem-main.bc" "${WORK}/libarchive-primary.a" "${WORK}/libarchive-dependencies.a"
    RESULT_VARIABLE result
    ERROR_VARIABLE error
)
if(result)
    message(FATAL_ERROR "bpf-capsule-ld failed: ${error}")
endif()

execute_process(
    COMMAND "${LLVM_NM}" "${WORK}/linked.bc"
    RESULT_VARIABLE result
    OUTPUT_VARIABLE symbols
    ERROR_VARIABLE error
)
if(result)
    message(FATAL_ERROR "llvm-nm failed: ${error}")
endif()

foreach(
    symbol
    IN
    ITEMS
        archive_entry
        archive_fp_entry
        archive_mem_entry
        archive_foo
        archive_bundle
        archive_override
        archive_bar
        archive_data
        sqrt
        fabs
        memcpy
        memmove
        memset
)
    if(NOT symbols MATCHES "[ \t]${symbol}([\r\n]|$)")
        message(FATAL_ERROR "linked module does not define ${symbol}:\n${symbols}")
    endif()
endforeach()

execute_process(
    COMMAND "${LLVM_NM}" --defined-only "${WORK}/linked.bc"
    RESULT_VARIABLE result
    OUTPUT_VARIABLE definitions
    ERROR_VARIABLE error
)
if(result)
    message(FATAL_ERROR "llvm-nm --defined-only failed: ${error}")
endif()

foreach(symbol IN ITEMS archive_optional archive_unused archive_missing)
    if(definitions MATCHES "[ \t]${symbol}([\r\n]|$)")
        message(FATAL_ERROR "unused archive member defined ${symbol}:\n${definitions}")
    endif()
endforeach()

execute_process(
    COMMAND "${LLVM_DIS}" "${WORK}/linked.bc" -o "${WORK}/linked.ll"
    RESULT_VARIABLE result
    ERROR_VARIABLE error
)
if(result)
    message(FATAL_ERROR "llvm-dis failed: ${error}")
endif()
file(READ "${WORK}/linked.ll" ir)
if(NOT ir MATCHES "define i64 @archive_override\\(i64 %x\\)[^}]*add i64 %x, 1000")
    message(FATAL_ERROR "strong definition did not override the archive's weak definition:\n${ir}")
endif()
if(ir MATCHES "icmp ne ptr @archive_optional")
    message(FATAL_ERROR "undefined external_weak symbol was not resolved to null:\n${ir}")
endif()
if(NOT ir MATCHES "icmp ne ptr @loader_optional")
    message(FATAL_ERROR "sectioned external_weak loader symbol was resolved locally:\n${ir}")
endif()
