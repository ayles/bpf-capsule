source_filename = "rejected-legacy-fetch.ll"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpfel"

define i64 @native(ptr %address) {
entry:
  %old = atomicrmw add ptr %address, i64 1 monotonic, align 8
  ret i64 %old
}
