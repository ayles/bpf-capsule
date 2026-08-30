source_filename = "softfloat-arithmetic.ll"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpfel"

define i32 @float_arithmetic(i32 %lhs, i32 %rhs) {
entry:
  %0 = call i32 @__bpf_fadd(i32 %lhs, i32 %rhs)
  %1 = call i32 @__bpf_fsub(i32 %0, i32 %rhs)
  %2 = call i32 @__bpf_fmul(i32 %1, i32 %rhs)
  %3 = call i32 @__bpf_fdiv(i32 %2, i32 %rhs)
  %4 = call i32 @__bpf_frem(i32 %3, i32 %rhs)
  %5 = call i32 @__bpf_fneg(i32 %4)
  ret i32 %5
}

define i64 @double_arithmetic(i64 %lhs, i64 %rhs) {
entry:
  %0 = call i64 @__bpf_dadd(i64 %lhs, i64 %rhs)
  %1 = call i64 @__bpf_dsub(i64 %0, i64 %rhs)
  %2 = call i64 @__bpf_dmul(i64 %1, i64 %rhs)
  %3 = call i64 @__bpf_ddiv(i64 %2, i64 %rhs)
  %4 = call i64 @__bpf_drem(i64 %3, i64 %rhs)
  %5 = call i64 @__bpf_dneg(i64 %4)
  ret i64 %5
}

declare i32 @__bpf_fadd(i32, i32)

declare i32 @__bpf_fsub(i32, i32)

declare i32 @__bpf_fmul(i32, i32)

declare i32 @__bpf_fdiv(i32, i32)

declare i32 @__bpf_frem(i32, i32)

declare i32 @__bpf_fneg(i32)

declare i64 @__bpf_dadd(i64, i64)

declare i64 @__bpf_dsub(i64, i64)

declare i64 @__bpf_dmul(i64, i64)

declare i64 @__bpf_ddiv(i64, i64)

declare i64 @__bpf_drem(i64, i64)

declare i64 @__bpf_dneg(i64)
