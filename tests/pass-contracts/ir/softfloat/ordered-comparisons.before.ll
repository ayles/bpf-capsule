source_filename = "softfloat-ordered-comparisons.ll"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpfel"

define i1 @always_false(double %lhs, double %rhs) {
entry:
  %result = fcmp false double %lhs, %rhs
  ret i1 %result
}

define i1 @ordered(double %lhs, double %rhs) {
entry:
  %result = fcmp ord double %lhs, %rhs
  ret i1 %result
}

define i1 @ordered_equal(double %lhs, double %rhs) {
entry:
  %result = fcmp oeq double %lhs, %rhs
  ret i1 %result
}

define i1 @ordered_greater(double %lhs, double %rhs) {
entry:
  %result = fcmp ogt double %lhs, %rhs
  ret i1 %result
}

define i1 @ordered_greater_equal(double %lhs, double %rhs) {
entry:
  %result = fcmp oge double %lhs, %rhs
  ret i1 %result
}

define i1 @ordered_less(double %lhs, double %rhs) {
entry:
  %result = fcmp olt double %lhs, %rhs
  ret i1 %result
}

define i1 @ordered_less_equal(double %lhs, double %rhs) {
entry:
  %result = fcmp ole double %lhs, %rhs
  ret i1 %result
}

define i1 @ordered_not_equal(double %lhs, double %rhs) {
entry:
  %result = fcmp one double %lhs, %rhs
  ret i1 %result
}

define i1 @always_true(double %lhs, double %rhs) {
entry:
  %result = fcmp true double %lhs, %rhs
  ret i1 %result
}
