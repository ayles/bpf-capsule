source_filename = "softfloat-conversions.ll"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpfel"

define i64 @extend_float(i32 %value) {
entry:
  %0 = call i64 @__bpf_f2d(i32 %value)
  ret i64 %0
}

define i32 @truncate_double(i64 %value) {
entry:
  %0 = call i32 @__bpf_d2f(i64 %value)
  ret i32 %0
}

define i32 @signed_to_float(i32 %value) {
entry:
  %0 = sext i32 %value to i64
  %1 = call i32 @__bpf_i2f(i64 %0)
  ret i32 %1
}

define i64 @signed_to_double(i64 %value) {
entry:
  %0 = call i64 @__bpf_i2d(i64 %value)
  ret i64 %0
}

define i32 @unsigned_to_float(i16 %value) {
entry:
  %0 = zext i16 %value to i64
  %1 = call i32 @__bpf_u2f(i64 %0)
  ret i32 %1
}

define i64 @unsigned_to_double(i64 %value) {
entry:
  %0 = call i64 @__bpf_u2d(i64 %value)
  ret i64 %0
}

define i16 @float_to_signed(i32 %value) {
entry:
  %0 = call i64 @__bpf_f2i(i32 %value)
  %1 = trunc i64 %0 to i16
  ret i16 %1
}

define i32 @float_to_unsigned(i32 %value) {
entry:
  %0 = call i64 @__bpf_f2u(i32 %value)
  %1 = trunc i64 %0 to i32
  ret i32 %1
}

define i32 @double_to_signed(i64 %value) {
entry:
  %0 = call i64 @__bpf_d2i(i64 %value)
  %1 = trunc i64 %0 to i32
  ret i32 %1
}

define i8 @double_to_unsigned(i64 %value) {
entry:
  %0 = call i64 @__bpf_d2u(i64 %value)
  %1 = trunc i64 %0 to i8
  ret i8 %1
}

declare i64 @__bpf_f2d(i32)

declare i32 @__bpf_d2f(i64)

declare i32 @__bpf_i2f(i64)

declare i64 @__bpf_i2d(i64)

declare i32 @__bpf_u2f(i64)

declare i64 @__bpf_u2d(i64)

declare i64 @__bpf_f2i(i32)

declare i64 @__bpf_f2u(i32)

declare i64 @__bpf_d2i(i64)

declare i64 @__bpf_d2u(i64)
