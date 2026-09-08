source_filename = "softfloat-ordered-comparisons.ll"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpfel"

define i1 @always_false(i64 %lhs, i64 %rhs) {
entry:
  ret i1 false
}

define i1 @ordered(i64 %lhs, i64 %rhs) {
entry:
  %0 = call i64 @__unorddf2(i64 %lhs, i64 %rhs)
  %1 = icmp eq i64 %0, 0
  ret i1 %1
}

define i1 @ordered_equal(i64 %lhs, i64 %rhs) {
entry:
  %0 = call i64 @__eqdf2(i64 %lhs, i64 %rhs)
  %1 = icmp eq i64 %0, 0
  ret i1 %1
}

define i1 @ordered_greater(i64 %lhs, i64 %rhs) {
entry:
  %0 = call i64 @__gedf2(i64 %lhs, i64 %rhs)
  %1 = icmp sgt i64 %0, 0
  ret i1 %1
}

define i1 @ordered_greater_equal(i64 %lhs, i64 %rhs) {
entry:
  %0 = call i64 @__gedf2(i64 %lhs, i64 %rhs)
  %1 = icmp sge i64 %0, 0
  ret i1 %1
}

define i1 @ordered_less(i64 %lhs, i64 %rhs) {
entry:
  %0 = call i64 @__ledf2(i64 %lhs, i64 %rhs)
  %1 = icmp slt i64 %0, 0
  ret i1 %1
}

define i1 @ordered_less_equal(i64 %lhs, i64 %rhs) {
entry:
  %0 = call i64 @__ledf2(i64 %lhs, i64 %rhs)
  %1 = icmp sle i64 %0, 0
  ret i1 %1
}

define i1 @ordered_not_equal(i64 %lhs, i64 %rhs) {
entry:
  %0 = call i64 @__eqdf2(i64 %lhs, i64 %rhs)
  %1 = icmp ne i64 %0, 0
  %2 = call i64 @__unorddf2(i64 %lhs, i64 %rhs)
  %3 = icmp eq i64 %2, 0
  %4 = and i1 %1, %3
  ret i1 %4
}

define i1 @always_true(i64 %lhs, i64 %rhs) {
entry:
  ret i1 true
}

declare i64 @__unorddf2(i64, i64)

declare i64 @__eqdf2(i64, i64)

declare i64 @__gedf2(i64, i64)

declare i64 @__ledf2(i64, i64)
