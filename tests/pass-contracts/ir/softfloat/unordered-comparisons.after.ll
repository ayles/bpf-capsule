source_filename = "softfloat-unordered-comparisons.ll"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpfel"

define i1 @unordered(i32 %lhs, i32 %rhs) {
entry:
  %0 = call i64 @__unordsf2(i32 %lhs, i32 %rhs)
  %1 = icmp ne i64 %0, 0
  ret i1 %1
}

define i1 @unordered_equal(i32 %lhs, i32 %rhs) {
entry:
  %0 = call i64 @__eqsf2(i32 %lhs, i32 %rhs)
  %1 = icmp eq i64 %0, 0
  %2 = call i64 @__unordsf2(i32 %lhs, i32 %rhs)
  %3 = icmp ne i64 %2, 0
  %4 = or i1 %1, %3
  ret i1 %4
}

define i1 @unordered_greater(i32 %lhs, i32 %rhs) {
entry:
  %0 = call i64 @__lesf2(i32 %lhs, i32 %rhs)
  %1 = icmp sgt i64 %0, 0
  ret i1 %1
}

define i1 @unordered_greater_equal(i32 %lhs, i32 %rhs) {
entry:
  %0 = call i64 @__lesf2(i32 %lhs, i32 %rhs)
  %1 = icmp sge i64 %0, 0
  ret i1 %1
}

define i1 @unordered_less(i32 %lhs, i32 %rhs) {
entry:
  %0 = call i64 @__gesf2(i32 %lhs, i32 %rhs)
  %1 = icmp slt i64 %0, 0
  ret i1 %1
}

define i1 @unordered_less_equal(i32 %lhs, i32 %rhs) {
entry:
  %0 = call i64 @__gesf2(i32 %lhs, i32 %rhs)
  %1 = icmp sle i64 %0, 0
  ret i1 %1
}

define i1 @unordered_not_equal(i32 %lhs, i32 %rhs) {
entry:
  %0 = call i64 @__eqsf2(i32 %lhs, i32 %rhs)
  %1 = icmp ne i64 %0, 0
  ret i1 %1
}

declare i64 @__unordsf2(i32, i32)

declare i64 @__eqsf2(i32, i32)

declare i64 @__lesf2(i32, i32)

declare i64 @__gesf2(i32, i32)
