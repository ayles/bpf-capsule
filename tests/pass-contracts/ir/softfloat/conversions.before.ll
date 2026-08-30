source_filename = "softfloat-conversions.ll"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpfel"

define double @extend_float(float %value) {
entry:
  %result = fpext float %value to double
  ret double %result
}

define float @truncate_double(double %value) {
entry:
  %result = fptrunc double %value to float
  ret float %result
}

define float @signed_to_float(i32 %value) {
entry:
  %result = sitofp i32 %value to float
  ret float %result
}

define double @signed_to_double(i64 %value) {
entry:
  %result = sitofp i64 %value to double
  ret double %result
}

define float @unsigned_to_float(i16 %value) {
entry:
  %result = uitofp i16 %value to float
  ret float %result
}

define double @unsigned_to_double(i64 %value) {
entry:
  %result = uitofp i64 %value to double
  ret double %result
}

define i16 @float_to_signed(float %value) {
entry:
  %result = fptosi float %value to i16
  ret i16 %result
}

define i32 @float_to_unsigned(float %value) {
entry:
  %result = fptoui float %value to i32
  ret i32 %result
}

define i32 @double_to_signed(double %value) {
entry:
  %result = fptosi double %value to i32
  ret i32 %result
}

define i8 @double_to_unsigned(double %value) {
entry:
  %result = fptoui double %value to i8
  ret i8 %result
}
