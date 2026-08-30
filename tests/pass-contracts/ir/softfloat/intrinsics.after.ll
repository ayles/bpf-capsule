source_filename = "softfloat-intrinsics.ll"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpfel"

; Function Attrs: nocallback nocreateundeforpoison nofree nosync nounwind speculatable willreturn memory(none)
declare float @llvm.fabs.f32(float) #0

; Function Attrs: nocallback nocreateundeforpoison nofree nosync nounwind speculatable willreturn memory(none)
declare double @llvm.pow.f64(double, double) #0

; Function Attrs: nocallback nocreateundeforpoison nofree nosync nounwind speculatable willreturn memory(none)
declare float @llvm.fma.f32(float, float, float) #0

; Function Attrs: nocallback nocreateundeforpoison nofree nosync nounwind speculatable willreturn memory(none)
declare float @llvm.fmuladd.f32(float, float, float) #0

define i32 @fabsf(i32 %value) {
entry:
  ret i32 %value
}

define i64 @pow(i64 %lhs, i64 %rhs) {
entry:
  ret i64 %lhs
}

define i32 @fmaf(i32 %a, i32 %b, i32 %c) {
entry:
  ret i32 %a
}

define { i32, i64, i32 } @use_intrinsics(i32 %f, i64 %d) {
entry:
  %0 = call i32 @fabsf(i32 %f)
  %1 = call i64 @pow(i64 %d, i64 4611686018427387904)
  %2 = call i32 @fmaf(i32 %f, i32 %f, i32 %f)
  %3 = insertvalue { i32, i64, i32 } poison, i32 %0, 0
  %4 = insertvalue { i32, i64, i32 } %3, i64 %1, 1
  %5 = insertvalue { i32, i64, i32 } %4, i32 %2, 2
  ret { i32, i64, i32 } %5
}

define i32 @use_fmuladd(i32 %a, i32 %b, i32 %c) {
entry:
  %0 = call i32 @__bpf_fmul(i32 %a, i32 %b)
  %1 = call i32 @__bpf_fadd(i32 %0, i32 %c)
  ret i32 %1
}

declare i32 @__bpf_fmul(i32, i32)

declare i32 @__bpf_fadd(i32, i32)

attributes #0 = { nocallback nocreateundeforpoison nofree nosync nounwind speculatable willreturn memory(none) }
