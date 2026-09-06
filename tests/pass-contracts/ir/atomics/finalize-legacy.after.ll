source_filename = "finalize-legacy.ll"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpfel"

define i64 @native(ptr %word, ptr %doubleword) {
entry:
  %add = atomicrmw add ptr %word, i32 1 monotonic, align 4
  %sub = atomicrmw sub ptr %doubleword, i64 1 monotonic, align 8
  %0 = load i64, ptr %doubleword, align 8
  store i64 0, ptr %doubleword, align 8
  ret i64 %0
}
