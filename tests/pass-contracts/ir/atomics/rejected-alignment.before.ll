source_filename = "validate-atomics-rejected-alignment.ll"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpfel"

@capsule_word = global i32 0, align 4

define i32 @managed() !bpf.capsule !0 {
entry:
  %value = load atomic i32, ptr @capsule_word monotonic, align 1
  ret i32 %value
}

!0 = !{}
