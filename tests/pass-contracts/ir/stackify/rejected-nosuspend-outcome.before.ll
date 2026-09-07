source_filename = "stackify-rejected-nosuspend-outcome.ll"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpfel"

@outcome = global i64 0

define i32 @bad() #0 {
entry:
  store i64 -4294967293, ptr @outcome, align 8, !bpf.capsule.outcome.store !0
  ret i32 0
}

attributes #0 = { "capsule.nosuspend" }

!0 = !{}
