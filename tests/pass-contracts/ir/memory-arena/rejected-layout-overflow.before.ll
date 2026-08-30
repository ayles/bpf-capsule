source_filename = "memory-arena-layout-overflow.ll"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpfel"

%arena_control = type { i32, i32, i64 }

@bpf_capsule_arena_control = global %arena_control zeroinitializer, section ".data.bpfctrl", align 8
@too_large = internal global [4294967297 x i8] zeroinitializer, align 8
@bpf_call_stack = internal global [4096 x i8] zeroinitializer, align 8, !bpf.fiber.stack.size !0

!0 = !{i64 4096}
