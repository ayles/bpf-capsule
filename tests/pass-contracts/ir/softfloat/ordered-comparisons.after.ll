source_filename = "softfloat-ordered-comparisons.ll"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpfel"

define i1 @always_false(i64 %lhs, i64 %rhs) {
entry:
  %0 = call i32 @__bpf_dcmp(i64 %lhs, i64 %rhs)
  %1 = icmp eq i32 %0, 2
  %2 = icmp eq i32 %0, -1
  %3 = icmp eq i32 %0, 0
  %4 = icmp eq i32 %0, 1
  ret i1 false
}

define i1 @ordered(i64 %lhs, i64 %rhs) {
entry:
  %0 = call i32 @__bpf_dcmp(i64 %lhs, i64 %rhs)
  %1 = icmp eq i32 %0, 2
  %2 = icmp eq i32 %0, -1
  %3 = icmp eq i32 %0, 0
  %4 = icmp eq i32 %0, 1
  %5 = xor i1 %1, true
  ret i1 %5
}

define i1 @ordered_equal(i64 %lhs, i64 %rhs) {
entry:
  %0 = call i32 @__bpf_dcmp(i64 %lhs, i64 %rhs)
  %1 = icmp eq i32 %0, 2
  %2 = icmp eq i32 %0, -1
  %3 = icmp eq i32 %0, 0
  %4 = icmp eq i32 %0, 1
  ret i1 %3
}

define i1 @ordered_greater(i64 %lhs, i64 %rhs) {
entry:
  %0 = call i32 @__bpf_dcmp(i64 %lhs, i64 %rhs)
  %1 = icmp eq i32 %0, 2
  %2 = icmp eq i32 %0, -1
  %3 = icmp eq i32 %0, 0
  %4 = icmp eq i32 %0, 1
  ret i1 %4
}

define i1 @ordered_greater_equal(i64 %lhs, i64 %rhs) {
entry:
  %0 = call i32 @__bpf_dcmp(i64 %lhs, i64 %rhs)
  %1 = icmp eq i32 %0, 2
  %2 = icmp eq i32 %0, -1
  %3 = icmp eq i32 %0, 0
  %4 = icmp eq i32 %0, 1
  %5 = or i1 %4, %3
  ret i1 %5
}

define i1 @ordered_less(i64 %lhs, i64 %rhs) {
entry:
  %0 = call i32 @__bpf_dcmp(i64 %lhs, i64 %rhs)
  %1 = icmp eq i32 %0, 2
  %2 = icmp eq i32 %0, -1
  %3 = icmp eq i32 %0, 0
  %4 = icmp eq i32 %0, 1
  ret i1 %2
}

define i1 @ordered_less_equal(i64 %lhs, i64 %rhs) {
entry:
  %0 = call i32 @__bpf_dcmp(i64 %lhs, i64 %rhs)
  %1 = icmp eq i32 %0, 2
  %2 = icmp eq i32 %0, -1
  %3 = icmp eq i32 %0, 0
  %4 = icmp eq i32 %0, 1
  %5 = or i1 %2, %3
  ret i1 %5
}

define i1 @ordered_not_equal(i64 %lhs, i64 %rhs) {
entry:
  %0 = call i32 @__bpf_dcmp(i64 %lhs, i64 %rhs)
  %1 = icmp eq i32 %0, 2
  %2 = icmp eq i32 %0, -1
  %3 = icmp eq i32 %0, 0
  %4 = icmp eq i32 %0, 1
  %5 = or i1 %2, %4
  ret i1 %5
}

define i1 @always_true(i64 %lhs, i64 %rhs) {
entry:
  %0 = call i32 @__bpf_dcmp(i64 %lhs, i64 %rhs)
  %1 = icmp eq i32 %0, 2
  %2 = icmp eq i32 %0, -1
  %3 = icmp eq i32 %0, 0
  %4 = icmp eq i32 %0, 1
  ret i1 true
}

declare i32 @__bpf_dcmp(i64, i64)
