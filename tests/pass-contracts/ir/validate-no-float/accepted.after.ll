source_filename = "validate-no-float.ll"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpfel"

define i64 @integers_only(i64 %lhs, i64 %rhs) {
entry:
  %result = mul i64 %lhs, %rhs
  ret i64 %result
}
