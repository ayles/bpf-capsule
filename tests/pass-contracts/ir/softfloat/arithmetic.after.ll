source_filename = "softfloat-arithmetic.ll"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpfel"

define i32 @float_arithmetic(i32 %lhs, i32 %rhs) {
entry:
  %0 = call i32 @__addsf3(i32 %lhs, i32 %rhs)
  %1 = call i32 @__subsf3(i32 %0, i32 %rhs)
  %2 = call i32 @__mulsf3(i32 %1, i32 %rhs)
  %3 = call i32 @__divsf3(i32 %2, i32 %rhs)
  %4 = call i32 @fmodf(i32 %3, i32 %rhs)
  %5 = call i32 @__negsf2(i32 %4)
  ret i32 %5
}

define i64 @double_arithmetic(i64 %lhs, i64 %rhs) {
entry:
  %0 = call i64 @__adddf3(i64 %lhs, i64 %rhs)
  %1 = call i64 @__subdf3(i64 %0, i64 %rhs)
  %2 = call i64 @__muldf3(i64 %1, i64 %rhs)
  %3 = call i64 @__divdf3(i64 %2, i64 %rhs)
  %4 = call i64 @fmod(i64 %3, i64 %rhs)
  %5 = call i64 @__negdf2(i64 %4)
  ret i64 %5
}

declare i32 @__addsf3(i32, i32)

declare i32 @__subsf3(i32, i32)

declare i32 @__mulsf3(i32, i32)

declare i32 @__divsf3(i32, i32)

declare i32 @fmodf(i32, i32)

declare i32 @__negsf2(i32)

declare i64 @__adddf3(i64, i64)

declare i64 @__subdf3(i64, i64)

declare i64 @__muldf3(i64, i64)

declare i64 @__divdf3(i64, i64)

declare i64 @fmod(i64, i64)

declare i64 @__negdf2(i64)
