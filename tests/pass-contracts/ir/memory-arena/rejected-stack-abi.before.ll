source_filename = "memory-arena-stack-abi.ll"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpfel"

%config = type { i32, i32, i32, i32, i32, i32, i32, i32, i32, i32, i32, i32, i64 }
%arena_control = type { i32, i32, i64 }

@bpf_capsule_config = constant %config { i32 0, i32 4096, i32 0, i32 0, i32 1, i32 3000, i32 1, i32 0, i32 1, i32 0, i32 1112556353, i32 5, i64 0 }, section ".rodata.bpfconfig", align 4
@bpf_capsule_arena_control = global %arena_control zeroinitializer, section ".data.bpfctrl", align 8
@bpf_call_stack = internal global [6000 x i8] zeroinitializer, align 8, !bpf.fiber.stack.size !0

!0 = !{i64 3000}
