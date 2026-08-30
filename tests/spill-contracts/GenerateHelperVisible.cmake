# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
if(NOT DEFINED OUTPUT OR NOT DEFINED WORD_COUNT OR WORD_COUNT LESS 48)
    message(FATAL_ERROR "GenerateHelperVisible.cmake needs OUTPUT and WORD_COUNT >= 48")
endif()

set(ir "; SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception\n")
string(APPEND ir
    "; A helper may access the complete declared buffer even when MIR contains\n"
    "; only one direct access. Relocated spills must not overlap its tail.\n"
    "target datalayout = \"e-m:e-p:64:64-i64:64-i128:128-n32:64-S128\"\n"
    "target triple = \"bpfel\"\n\n"
    "%fiber.control = type { i64, i64 }\n"
    "@bpf_capsule_fibers = dso_local global [1 x %fiber.control] zeroinitializer, section \".bss.bpfctrl\", align 8\n"
    "@bpf_call_stack = dso_local global [1 x [262144 x i8]] zeroinitializer, section \".bss.stack\", align 8\n"
    "@helper_visible_noise = dso_local global i64 1, section \".data.helper_visible\", align 8\n"
    "@helper_visible_result = dso_local global i64 0, section \".bss.helper_visible\", align 8\n"
    "@_license = dso_local global [4 x i8] c\"GPL\\00\", section \"license\", align 1\n\n"
    "define dso_local i64 @helper_visible(i64 %seed) #0 !bpf.capsule.allocation.unit !0 !bpf.capsule.stack.size !1 {\n"
    "entry:\n"
    "  %guard = alloca [64 x i8], align 8\n"
    "  %buffer = alloca [288 x i8], align 8\n")

math(EXPR last_word "${WORD_COUNT} - 1")
foreach(index RANGE 0 ${last_word})
    string(APPEND ir "  %slot${index} = alloca i64, align 8\n")
endforeach()
string(APPEND ir
    "  %stack = getelementptr inbounds [1 x [262144 x i8]], ptr @bpf_call_stack, i64 0, i64 0, i64 0\n"
    "  call void asm sideeffect \"# bpf_capsule_stack_anchor\", \"r\"(ptr %stack)\n"
    "  %guard.first = getelementptr inbounds [64 x i8], ptr %guard, i64 0, i64 0\n"
    "  %guard.input = and i64 %seed, 2097151\n"
    "  store volatile i64 %guard.input, ptr %guard.first, align 8\n"
    "  %buffer.first = getelementptr inbounds [288 x i8], ptr %buffer, i64 0, i64 0\n"
    "  store volatile i8 0, ptr %buffer.first, align 8\n"
    "  %helper.result = call i64 inttoptr (i64 113 to ptr)(ptr %buffer.first, i32 288, ptr null)\n")
foreach(index RANGE 0 ${last_word})
    string(APPEND ir
        "  %input${index} = load volatile i64, ptr @helper_visible_noise, align 8\n"
        "  %value${index} = add i64 %input${index}, ${index}\n"
        "  store volatile i64 %value${index}, ptr %slot${index}, align 8\n")
endforeach()
foreach(index RANGE 0 ${last_word})
    string(APPEND ir "  %load${index} = load volatile i64, ptr %slot${index}, align 8\n")
endforeach()
string(APPEND ir "  %sum0 = xor i64 %load0, %load1\n")
foreach(index RANGE 2 ${last_word})
    math(EXPR current_sum "${index} - 1")
    math(EXPR previous_sum "${index} - 2")
    string(APPEND ir "  %sum${current_sum} = xor i64 %sum${previous_sum}, %load${index}\n")
endforeach()
math(EXPR last_sum "${last_word} - 1")
string(APPEND ir
    "  %guard.value = load volatile i64, ptr %guard.first, align 8\n"
    "  %combined = xor i64 %sum${last_sum}, %helper.result\n"
    "  %result = xor i64 %combined, %guard.value\n"
    "  ret i64 %result\n"
    "}\n\n"
    "define dso_local i32 @helper_visible_run() section \"syscall\" {\n"
    "entry:\n"
    "  %value = call i64 @helper_visible(i64 4096)\n"
    "  store volatile i64 %value, ptr @helper_visible_result, align 8\n"
    "  ret i32 0\n"
    "}\n\n"
    "attributes #0 = { noinline nounwind }\n\n"
    "!0 = !{}\n"
    "!1 = !{i64 262144}\n")

file(WRITE "${OUTPUT}" "${ir}")
