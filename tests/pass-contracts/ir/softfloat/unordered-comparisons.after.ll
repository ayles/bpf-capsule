source_filename = "softfloat-unordered-comparisons.ll"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpfel"

define i1 @unordered(i32 %lhs, i32 %rhs) {
entry:
  %0 = call i32 @__bpf_fcmp(i32 %lhs, i32 %rhs)
  %1 = icmp eq i32 %0, 2
  %2 = icmp eq i32 %0, -1
  %3 = icmp eq i32 %0, 0
  %4 = icmp eq i32 %0, 1
  ret i1 %1
}

define i1 @unordered_equal(i32 %lhs, i32 %rhs) {
entry:
  %0 = call i32 @__bpf_fcmp(i32 %lhs, i32 %rhs)
  %1 = icmp eq i32 %0, 2
  %2 = icmp eq i32 %0, -1
  %3 = icmp eq i32 %0, 0
  %4 = icmp eq i32 %0, 1
  %5 = or i1 %3, %1
  ret i1 %5
}

define i1 @unordered_greater(i32 %lhs, i32 %rhs) {
entry:
  %0 = call i32 @__bpf_fcmp(i32 %lhs, i32 %rhs)
  %1 = icmp eq i32 %0, 2
  %2 = icmp eq i32 %0, -1
  %3 = icmp eq i32 %0, 0
  %4 = icmp eq i32 %0, 1
  %5 = or i1 %4, %1
  ret i1 %5
}

define i1 @unordered_greater_equal(i32 %lhs, i32 %rhs) {
entry:
  %0 = call i32 @__bpf_fcmp(i32 %lhs, i32 %rhs)
  %1 = icmp eq i32 %0, 2
  %2 = icmp eq i32 %0, -1
  %3 = icmp eq i32 %0, 0
  %4 = icmp eq i32 %0, 1
  %5 = or i1 %4, %3
  %6 = or i1 %5, %1
  ret i1 %6
}

define i1 @unordered_less(i32 %lhs, i32 %rhs) {
entry:
  %0 = call i32 @__bpf_fcmp(i32 %lhs, i32 %rhs)
  %1 = icmp eq i32 %0, 2
  %2 = icmp eq i32 %0, -1
  %3 = icmp eq i32 %0, 0
  %4 = icmp eq i32 %0, 1
  %5 = or i1 %2, %1
  ret i1 %5
}

define i1 @unordered_less_equal(i32 %lhs, i32 %rhs) {
entry:
  %0 = call i32 @__bpf_fcmp(i32 %lhs, i32 %rhs)
  %1 = icmp eq i32 %0, 2
  %2 = icmp eq i32 %0, -1
  %3 = icmp eq i32 %0, 0
  %4 = icmp eq i32 %0, 1
  %5 = or i1 %2, %3
  %6 = or i1 %5, %1
  ret i1 %6
}

define i1 @unordered_not_equal(i32 %lhs, i32 %rhs) {
entry:
  %0 = call i32 @__bpf_fcmp(i32 %lhs, i32 %rhs)
  %1 = icmp eq i32 %0, 2
  %2 = icmp eq i32 %0, -1
  %3 = icmp eq i32 %0, 0
  %4 = icmp eq i32 %0, 1
  %5 = xor i1 %3, true
  ret i1 %5
}

declare i32 @__bpf_fcmp(i32, i32)
