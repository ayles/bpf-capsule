source_filename = "softfloat-fpclass.ll"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpfel"

; Function Attrs: nocallback nocreateundeforpoison nofree nosync nounwind speculatable willreturn memory(none)
declare i1 @llvm.is.fpclass.f32(float, i32 immarg) #0

; Function Attrs: nocallback nocreateundeforpoison nofree nosync nounwind speculatable willreturn memory(none)
declare i1 @llvm.is.fpclass.f64(double, i32 immarg) #0

define i1 @selected_f32(i32 %value) {
entry:
  %0 = and i32 %value, 2147483647
  %1 = icmp ugt i32 %0, 2139095040
  %2 = and i32 %value, 4194304
  %3 = icmp ne i32 %2, 0
  %4 = and i1 %1, %3
  %5 = or i1 false, %4
  %6 = icmp eq i32 %0, 2139095040
  %7 = icmp slt i32 %value, 0
  %8 = and i1 %6, %7
  %9 = or i1 %5, %8
  %10 = and i32 %0, 2139095040
  %11 = icmp ne i32 %10, 0
  %12 = icmp ne i32 %10, 2139095040
  %13 = and i1 %11, %12
  %14 = xor i1 %7, true
  %15 = and i1 %13, %14
  %16 = or i1 %9, %15
  %17 = and i32 %0, 2139095040
  %18 = icmp eq i32 %17, 0
  %19 = icmp ne i32 %0, 0
  %20 = and i1 %18, %19
  %21 = and i1 %20, %7
  %22 = or i1 %16, %21
  %23 = icmp eq i32 %0, 0
  %24 = xor i1 %7, true
  %25 = and i1 %23, %24
  %26 = or i1 %22, %25
  ret i1 %26
}

define i1 @selected_f64(i64 %value) {
entry:
  %0 = and i64 %value, 9223372036854775807
  %1 = icmp ugt i64 %0, 9218868437227405312
  %2 = and i64 %value, 2251799813685248
  %3 = icmp ne i64 %2, 0
  %4 = xor i1 %3, true
  %5 = and i1 %1, %4
  %6 = or i1 false, %5
  %7 = icmp eq i64 %0, 9218868437227405312
  %8 = icmp slt i64 %value, 0
  %9 = xor i1 %8, true
  %10 = and i1 %7, %9
  %11 = or i1 %6, %10
  %12 = and i64 %0, 9218868437227405312
  %13 = icmp ne i64 %12, 0
  %14 = icmp ne i64 %12, 9218868437227405312
  %15 = and i1 %13, %14
  %16 = and i1 %15, %8
  %17 = or i1 %11, %16
  %18 = and i64 %0, 9218868437227405312
  %19 = icmp eq i64 %18, 0
  %20 = icmp ne i64 %0, 0
  %21 = and i1 %19, %20
  %22 = xor i1 %8, true
  %23 = and i1 %21, %22
  %24 = or i1 %17, %23
  %25 = icmp eq i64 %0, 0
  %26 = and i1 %25, %8
  %27 = or i1 %24, %26
  ret i1 %27
}

define i1 @all_f32(i32 %value) {
entry:
  ret i1 true
}

define i1 @none_f64(i64 %value) {
entry:
  ret i1 false
}

attributes #0 = { nocallback nocreateundeforpoison nofree nosync nounwind speculatable willreturn memory(none) }
