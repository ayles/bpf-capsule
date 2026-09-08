; SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
target triple = "bpfel"

define i128 @multiply(i128 %a, i128 %b) {
  %product = mul i128 %a, %b
  ret i128 %product
}

declare {i64, i1} @llvm.umul.with.overflow.i64(i64, i64)

define {i64, i1} @multiply_overflow(i64 %a, i64 %b) {
  %product = call {i64, i1} @llvm.umul.with.overflow.i64(i64 %a, i64 %b)
  ret {i64, i1} %product
}
