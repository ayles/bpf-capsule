source_filename = "validate-atomics-rejected-sectioned-subword.ll"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpfel"

@sectioned = global i16 0, section ".data.sectioned", align 2

define void @managed(i16 %value) !bpf.capsule !0 {
entry:
  %old = atomicrmw or ptr @sectioned, i16 %value seq_cst, align 2
  ret void
}

!0 = !{}
