source_filename = "softfloat-intrinsics.ll"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpfel"

define float @fabsf(float %value) {
entry:
  ret float %value
}

define double @pow(double %lhs, double %rhs) {
entry:
  ret double %lhs
}

define float @fmaf(float %a, float %b, float %c) {
entry:
  ret float %a
}

define { float, double, float } @use_intrinsics(float %f, double %d) {
entry:
  %absolute = call float @llvm.fabs.f32(float %f)
  %power = call double @llvm.pow.f64(double %d, double 2.000000e+00)
  %fused = call float @llvm.fma.f32(float %f, float %f, float %f)
  %first = insertvalue { float, double, float } poison, float %absolute, 0
  %second = insertvalue { float, double, float } %first, double %power, 1
  %result = insertvalue { float, double, float } %second, float %fused, 2
  ret { float, double, float } %result
}

define float @use_fmuladd(float %a, float %b, float %c) {
entry:
  %result = call float @llvm.fmuladd.f32(float %a, float %b, float %c)
  ret float %result
}

; Function Attrs: nocallback nocreateundeforpoison nofree nosync nounwind speculatable willreturn memory(none)
declare float @llvm.fabs.f32(float) #0

; Function Attrs: nocallback nocreateundeforpoison nofree nosync nounwind speculatable willreturn memory(none)
declare double @llvm.pow.f64(double, double) #0

; Function Attrs: nocallback nocreateundeforpoison nofree nosync nounwind speculatable willreturn memory(none)
declare float @llvm.fma.f32(float, float, float) #0

; Function Attrs: nocallback nocreateundeforpoison nofree nosync nounwind speculatable willreturn memory(none)
declare float @llvm.fmuladd.f32(float, float, float) #0

attributes #0 = { nocallback nocreateundeforpoison nofree nosync nounwind speculatable willreturn memory(none) }
