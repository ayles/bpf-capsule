source_filename = "memory-fixed-image-budget.ll"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpfel"

%image = type { i8, [2093056 x i8] }

@too_large_image = internal global %image { i8 1, [2093056 x i8] zeroinitializer }, align 8
@bpf_call_stack = internal global [4096 x i8] zeroinitializer, align 8, !bpf.fiber.stack.size !0

!0 = !{i64 4096}
