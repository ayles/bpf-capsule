source_filename = "inline-policy-o2.ll"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpfel"

define internal i32 @ordinary(i32 %value) {
entry:
  %result = add i32 %value, 3
  ret i32 %result
}

; Function Attrs: alwaysinline
define internal i32 @forced(i32 %value) #0 {
entry:
  %result = mul i32 %value, 5
  ret i32 %result
}

; Function Attrs: noinline
define internal i32 @blocked(i32 %value) #1 {
entry:
  %result = sub i32 %value, 7
  ret i32 %result
}

define i32 @caller(i32 %value) {
entry:
  %a = call i32 @ordinary(i32 %value)
  %b = call i32 @forced(i32 %a)
  %c = call i32 @blocked(i32 %b)
  ret i32 %c
}

attributes #0 = { alwaysinline }
attributes #1 = { noinline }
