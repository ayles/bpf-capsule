source_filename = "split-shift63.ll"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpfel"

define i64 @shift64(i64 %value, i64 %amount) {
entry:
  %ashr63 = ashr i64 %value, 63
  %lshr63 = lshr i64 %value, 63
  %unchanged.constant = lshr i64 %value, 62
  %unchanged.dynamic = ashr i64 %value, %amount
  %a = add i64 %ashr63, %lshr63
  %b = add i64 %unchanged.constant, %unchanged.dynamic
  %result = add i64 %a, %b
  ret i64 %result
}

define i32 @shift32(i32 %value) {
entry:
  %unchanged.width = ashr i32 %value, 63
  ret i32 %unchanged.width
}
