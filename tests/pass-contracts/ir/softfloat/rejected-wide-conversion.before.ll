source_filename = "softfloat-rejected-wide-conversion.ll"
target triple = "bpfel"

define double @wide_conversion(i128 %value) {
entry:
  %result = sitofp i128 %value to double
  ret double %result
}
