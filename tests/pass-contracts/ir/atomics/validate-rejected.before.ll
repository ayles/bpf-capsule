source_filename = "validate-atomics-rejected.ll"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpfel"

@capsule_counter = global i64 0

define i64 @managed(i64 %value) !bpf.capsule !0 {
entry:
  %old = atomicrmw add ptr @capsule_counter, i64 %value monotonic, align 8
  ret i64 %old
}

!0 = !{}
