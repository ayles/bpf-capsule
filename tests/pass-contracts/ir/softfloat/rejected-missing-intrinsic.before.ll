source_filename = "softfloat-rejected-missing-intrinsic.ll"
target triple = "bpfel"

define double @caller(double %value) {
entry:
  %result = call double @llvm.sqrt.f64(double %value)
  ret double %result
}

; Function Attrs: nocallback nocreateundeforpoison nofree nosync nounwind speculatable willreturn memory(none)
declare double @llvm.sqrt.f64(double) #0

attributes #0 = { nocallback nocreateundeforpoison nofree nosync nounwind speculatable willreturn memory(none) }
