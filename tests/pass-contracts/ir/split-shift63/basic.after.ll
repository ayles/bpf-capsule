source_filename = "split-shift63.ll"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpfel"

define i64 @shift64(i64 %value, i64 %amount) {
entry:
  %0 = ashr i64 %value, 32
  %1 = ashr i64 %0, 31
  %2 = lshr i64 %value, 32
  %3 = lshr i64 %2, 31
  %unchanged.constant = lshr i64 %value, 62
  %unchanged.dynamic = ashr i64 %value, %amount
  %a = add i64 %1, %3
  %b = add i64 %unchanged.constant, %unchanged.dynamic
  %result = add i64 %a, %b
  ret i64 %result
}

define i32 @shift32(i32 %value) {
entry:
  %unchanged.width = ashr i32 %value, 63
  ret i32 %unchanged.width
}
