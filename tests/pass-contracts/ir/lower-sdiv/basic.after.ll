source_filename = "lower-sdiv.ll"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpfel"

define i64 @wide(i64 %lhs, i64 %rhs) {
entry:
  %0 = ashr i64 %lhs, 63
  %1 = ashr i64 %rhs, 63
  %2 = xor i64 %lhs, %0
  %3 = sub i64 %2, %0
  %4 = xor i64 %rhs, %1
  %5 = sub i64 %4, %1
  %6 = udiv i64 %3, %5
  %7 = xor i64 %0, %1
  %8 = xor i64 %6, %7
  %9 = sub i64 %8, %7
  %10 = ashr i64 %lhs, 63
  %11 = ashr i64 %rhs, 63
  %12 = xor i64 %lhs, %10
  %13 = sub i64 %12, %10
  %14 = xor i64 %rhs, %11
  %15 = sub i64 %14, %11
  %16 = urem i64 %13, %15
  %17 = xor i64 %16, %10
  %18 = sub i64 %17, %10
  %unsigned = udiv i64 %lhs, %rhs
  %a = add i64 %9, %18
  %result = add i64 %a, %unsigned
  ret i64 %result
}

define i16 @narrow(i16 %lhs, i16 %rhs) {
entry:
  %0 = sext i16 %lhs to i32
  %1 = sext i16 %rhs to i32
  %2 = ashr i32 %0, 31
  %3 = ashr i32 %1, 31
  %4 = xor i32 %0, %2
  %5 = sub i32 %4, %2
  %6 = xor i32 %1, %3
  %7 = sub i32 %6, %3
  %8 = udiv i32 %5, %7
  %9 = xor i32 %2, %3
  %10 = xor i32 %8, %9
  %11 = sub i32 %10, %9
  %12 = trunc i32 %11 to i16
  %13 = sext i16 %lhs to i32
  %14 = sext i16 %rhs to i32
  %15 = ashr i32 %13, 31
  %16 = ashr i32 %14, 31
  %17 = xor i32 %13, %15
  %18 = sub i32 %17, %15
  %19 = xor i32 %14, %16
  %20 = sub i32 %19, %16
  %21 = urem i32 %18, %20
  %22 = xor i32 %21, %15
  %23 = sub i32 %22, %15
  %24 = trunc i32 %23 to i16
  %result = add i16 %12, %24
  ret i16 %result
}
