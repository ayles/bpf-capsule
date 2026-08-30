source_filename = "lower-capsule-exit-rejected-malformed.ll"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpfel"

declare i32 @__bpf_capsule_exit(i32)
