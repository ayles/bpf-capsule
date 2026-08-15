# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
if(NOT DEFINED OUTPUT
   OR NOT DEFINED VALUE_COUNT
   OR VALUE_COUNT LESS 1025
)
    message(FATAL_ERROR "generate-pressure.cmake needs OUTPUT and VALUE_COUNT >= 1025")
endif()

set(source "// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception\n")
string(APPEND source "// Generated adversarial register-pressure regression.\n")
string(APPEND source
       "#include <linux/bpf.h>\n#include <bpf/bpf_helpers.h>\n\n#include \"bpf_capsule.h\"\n\n"
)
string(APPEND source "#define PRESSURE_VALUE_COUNT ${VALUE_COUNT}u\n\n")
string(
    APPEND
    source
    "volatile unsigned long long pressure_input[PRESSURE_VALUE_COUNT + 1] SEC(\".bss.pressure_input\");\n"
)
string(APPEND source "volatile unsigned long long pressure_output SEC(\".bss.pressure_output\");\n")
string(APPEND source
       "volatile struct capsule_result pressure_result SEC(\".bss.pressure_result\");\n\n"
)
string(APPEND source "__attribute__((noinline)) static unsigned long long pressure_body(void) {\n")

math(EXPR last_value "${VALUE_COUNT} - 1")
foreach(index RANGE 0 ${last_value})
    string(APPEND source
           "    unsigned long long value${index} = pressure_input[${index}] * 10ull;\n"
    )
endforeach()

# Every value is live at the final volatile load. Using the key in every term
# prevents the optimizer or scheduler from interleaving the recurrence with
# the input loads and artificially reducing the pressure.
string(APPEND source "    unsigned long long key = pressure_input[PRESSURE_VALUE_COUNT];\n"
       "    unsigned long long result = key;\n"
)
foreach(index RANGE 0 ${last_value})
    string(APPEND source
           "    result = result * 6364136223846793005ull + (value${index} ^ (key + ${index}ull));\n"
    )
endforeach()
string(APPEND source "    return result;\n}\n\n")
string(
    APPEND
    source
    "SEC(\"syscall\")\n"
    "int pressure_run(void) {\n"
    "    pressure_result = capsule_call(&pressure_output, pressure_body);\n"
    "    return 0;\n"
    "}\n\n"
    "char _license[] SEC(\"license\") = \"GPL\";\n"
)

file(WRITE "${OUTPUT}" "${source}")
