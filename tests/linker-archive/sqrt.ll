declare double @llvm.fabs.f64(double)

define double @sqrt(double %x) {
entry:
  %result = call double @llvm.fabs.f64(double %x)
  ret double %result
}
