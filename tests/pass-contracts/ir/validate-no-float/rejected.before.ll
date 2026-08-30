source_filename = "validate-no-float-rejected.ll"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpfel"

define float @floating_point_survived(float %lhs, float %rhs) {
entry:
  %result = fadd float %lhs, %rhs
  ret float %result
}
