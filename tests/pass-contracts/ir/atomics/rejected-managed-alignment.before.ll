source_filename = "managed-atomic-alignment.ll"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpfel"

define void @managed(ptr %address) !bpf.capsule !0 {
entry:
  %old = atomicrmw add ptr %address, i64 1 seq_cst, align 4
  ret void
}

!0 = !{}
