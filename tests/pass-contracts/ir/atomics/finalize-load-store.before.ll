source_filename = "finalize-atomic-load-store.ll"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpfel"

define i64 @atomic_access(ptr %pointer, i64 %value) {
entry:
  %old = load atomic volatile i64, ptr %pointer monotonic, align 8
  store atomic volatile i64 %value, ptr %pointer unordered, align 8
  %plain = load i64, ptr %pointer, align 8
  %result = add i64 %old, %plain
  ret i64 %result
}
