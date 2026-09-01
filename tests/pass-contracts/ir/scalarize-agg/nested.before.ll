source_filename = "scalarize-agg.ll"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpfel"

%nested = type { i32, [2 x i16] }

define %nested @copy(ptr %source, ptr %destination) {
entry:
  %value = load volatile %nested, ptr %source, align 4
  store volatile %nested %value, ptr %destination, align 4
  ret %nested %value
}

define i128 @copy_i128(ptr %source, ptr %destination) {
entry:
  %value = load volatile i128, ptr %source, align 16
  store volatile i128 %value, ptr %destination, align 16
  ret i128 %value
}
