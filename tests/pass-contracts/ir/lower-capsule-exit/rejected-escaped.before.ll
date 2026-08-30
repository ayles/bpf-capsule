source_filename = "lower-capsule-exit-rejected-escaped.ll"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpfel"

@escaped_exit = global ptr @__bpf_capsule_exit

declare void @__bpf_capsule_exit(i32)
