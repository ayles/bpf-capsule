source_filename = "rejected-legacy-cas.ll"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpfel"

define void @native(ptr %address) {
entry:
  %result = cmpxchg ptr %address, i64 0, i64 1 monotonic monotonic, align 8
  ret void
}
