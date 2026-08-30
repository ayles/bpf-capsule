source_filename = "validate-atomics-rejected-fence.ll"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpfel"

define void @managed() !bpf.capsule !0 {
entry:
  fence seq_cst
  ret void
}

!0 = !{}
