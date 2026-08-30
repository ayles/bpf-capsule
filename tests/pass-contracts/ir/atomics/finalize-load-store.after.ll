source_filename = "finalize-atomic-load-store.ll"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpfel"

define i64 @atomic_access(ptr %pointer, i64 %value) {
entry:
  %0 = load volatile i64, ptr %pointer, align 8
  store volatile i64 %value, ptr %pointer, align 8
  %plain = load i64, ptr %pointer, align 8
  %result = add i64 %0, %plain
  ret i64 %result
}
