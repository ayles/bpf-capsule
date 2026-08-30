source_filename = "softfloat-arithmetic.ll"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpfel"

define float @float_arithmetic(float %lhs, float %rhs) {
entry:
  %added = fadd float %lhs, %rhs
  %subtracted = fsub float %added, %rhs
  %multiplied = fmul float %subtracted, %rhs
  %divided = fdiv float %multiplied, %rhs
  %remainder = frem float %divided, %rhs
  %negated = fneg float %remainder
  ret float %negated
}

define double @double_arithmetic(double %lhs, double %rhs) {
entry:
  %added = fadd double %lhs, %rhs
  %subtracted = fsub double %added, %rhs
  %multiplied = fmul double %subtracted, %rhs
  %divided = fdiv double %multiplied, %rhs
  %remainder = frem double %divided, %rhs
  %negated = fneg double %remainder
  ret double %negated
}
