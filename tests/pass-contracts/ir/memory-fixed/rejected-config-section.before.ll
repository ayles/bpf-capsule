source_filename = "memory-fixed-config-section.ll"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpfel"

%config = type { i32, i32, i32, i32, i32, i32, i32, i32, i32, i32, i32, i32, i64 }
%map = type { ptr }

@bpf_capsule_config = constant %config { i32 0, i32 4096, i32 0, i32 0, i32 1, i32 4096, i32 1, i32 0, i32 0, i32 0, i32 1112556353, i32 5, i64 0 }, section ".rodata.wrong", align 4
@bpf_heap_array = global %map zeroinitializer, section ".maps", align 8
@bpf_call_stack = internal global [4096 x i8] zeroinitializer, align 8, !bpf.fiber.stack.size !0

!0 = !{i64 4096}
