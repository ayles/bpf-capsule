source_filename = "memory-arena-control-state.ll"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpfel"

%arena_control = type { i32, i32, i64 }

@bpf_capsule_arena_control = global %arena_control { i32 2, i32 0, i64 0 }, section ".data.bpfctrl", align 8
