source_filename = "lower-managed-atomics-fixed.ll"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpfel"

@word = global i32 0, align 4
@wide = global i64 0, align 8

define i64 @managed(i32 %word.value, i64 %wide.value) !bpf.capsule !0 {
entry:
  %and = atomicrmw and ptr @word, i32 %word.value seq_cst, align 4
  %or = atomicrmw or ptr @wide, i64 %wide.value seq_cst, align 8
  %xor = atomicrmw xor ptr @wide, i64 %wide.value seq_cst, align 8
  %and.wide = zext i32 %and to i64
  %sum = add i64 %or, %and.wide
  %result = add i64 %sum, %xor
  ret i64 %result
}

!0 = !{}
