; SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
; Memory keeps its source aggregate layout; SSA values use an integer shadow
; aggregate. GEPs must continue to select the original floating field type.

target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpfel"

%pair = type { i32, double, i64 }

@initial = global %pair { i32 7, double 3.500000e+00, i64 9 }

define i64 @soft_float_aggregate(ptr %output) {
entry:
  %local = alloca %pair, align 8
  store %pair { i32 1, double 2.500000e+00, i64 3 }, ptr %local, align 8
  %field = getelementptr inbounds %pair, ptr %local, i32 0, i32 1
  %value = load double, ptr %field, align 8
  %aggregate = load %pair, ptr %local, align 8
  %extracted = extractvalue %pair %aggregate, 1
  %inserted = insertvalue %pair %aggregate, double %value, 1
  store %pair %inserted, ptr %output, align 8
  %sum = fadd double %value, %extracted
  %bits = bitcast double %sum to i64
  ret i64 %bits
}
