source_filename = "lower-sdiv.ll"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpfel"

define i64 @wide(i64 %lhs, i64 %rhs) {
entry:
  %quotient = sdiv i64 %lhs, %rhs
  %remainder = srem i64 %lhs, %rhs
  %unsigned = udiv i64 %lhs, %rhs
  %a = add i64 %quotient, %remainder
  %result = add i64 %a, %unsigned
  ret i64 %result
}

define i16 @narrow(i16 %lhs, i16 %rhs) {
entry:
  %quotient = sdiv i16 %lhs, %rhs
  %remainder = srem i16 %lhs, %rhs
  %result = add i16 %quotient, %remainder
  ret i16 %result
}
