source_filename = "validate-atomics-rejected-cmpxchg.ll"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpfel"

@capsule_word = global i32 0, align 4

define void @managed() !bpf.capsule !0 {
entry:
  %pair = cmpxchg ptr @capsule_word, i32 0, i32 1 seq_cst seq_cst, align 4
  ret void
}

!0 = !{}
