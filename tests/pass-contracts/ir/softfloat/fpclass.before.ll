source_filename = "softfloat-fpclass.ll"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpfel"

define i1 @selected_f32(float %value) {
entry:
  %result = call i1 @llvm.is.fpclass.f32(float %value, /* (qnan ninf pzero nsub pnorm) */ i32 342)
  ret i1 %result
}

define i1 @selected_f64(double %value) {
entry:
  %result = call i1 @llvm.is.fpclass.f64(double %value, /* (snan pinf nzero psub nnorm) */ i32 681)
  ret i1 %result
}

define i1 @all_f32(float %value) {
entry:
  %result = call i1 @llvm.is.fpclass.f32(float %value, /* (all) */ i32 1023)
  ret i1 %result
}

define i1 @none_f64(double %value) {
entry:
  %result = call i1 @llvm.is.fpclass.f64(double %value, /* (none) */ i32 0)
  ret i1 %result
}

; Function Attrs: nocallback nocreateundeforpoison nofree nosync nounwind speculatable willreturn memory(none)
declare i1 @llvm.is.fpclass.f32(float, i32 immarg) #0

; Function Attrs: nocallback nocreateundeforpoison nofree nosync nounwind speculatable willreturn memory(none)
declare i1 @llvm.is.fpclass.f64(double, i32 immarg) #0

attributes #0 = { nocallback nocreateundeforpoison nofree nosync nounwind speculatable willreturn memory(none) }
