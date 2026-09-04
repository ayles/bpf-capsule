declare double @llvm.sqrt.f64(double)

define double @archive_fp_entry(double %x) {
entry:
  %result = call double @llvm.sqrt.f64(double %x)
  ret double %result
}
