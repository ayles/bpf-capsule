source_filename = "softfloat-unordered-comparisons.ll"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpfel"

define i1 @unordered(float %lhs, float %rhs) {
entry:
  %result = fcmp uno float %lhs, %rhs
  ret i1 %result
}

define i1 @unordered_equal(float %lhs, float %rhs) {
entry:
  %result = fcmp ueq float %lhs, %rhs
  ret i1 %result
}

define i1 @unordered_greater(float %lhs, float %rhs) {
entry:
  %result = fcmp ugt float %lhs, %rhs
  ret i1 %result
}

define i1 @unordered_greater_equal(float %lhs, float %rhs) {
entry:
  %result = fcmp uge float %lhs, %rhs
  ret i1 %result
}

define i1 @unordered_less(float %lhs, float %rhs) {
entry:
  %result = fcmp ult float %lhs, %rhs
  ret i1 %result
}

define i1 @unordered_less_equal(float %lhs, float %rhs) {
entry:
  %result = fcmp ule float %lhs, %rhs
  ret i1 %result
}

define i1 @unordered_not_equal(float %lhs, float %rhs) {
entry:
  %result = fcmp une float %lhs, %rhs
  ret i1 %result
}
