source_filename = "lower-sdiv-rejected.ll"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64:128-S128"
target triple = "bpfel"

define i128 @too_wide(i128 %lhs, i128 %rhs) {
entry:
  %result = sdiv i128 %lhs, %rhs
  ret i128 %result
}
