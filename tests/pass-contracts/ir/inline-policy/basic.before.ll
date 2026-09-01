source_filename = "inline-policy.ll"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpfel"

; Function Attrs: alwaysinline
define i32 @ordinary(i32 %value) #0 {
entry:
  ret i32 %value
}

; Function Attrs: alwaysinline
define available_externally i32 @c99_inline(i32 %value) #0 {
entry:
  ret i32 %value
}

; Function Attrs: alwaysinline
define i64 @bpf_heap_load64(i64 %address) #1 {
entry:
  ret i64 %address
}

define i32 @plain(i32 %value) {
entry:
  ret i32 %value
}

; Function Attrs: alwaysinline
define i32 @variadic(i32 %value, ...) #0 {
entry:
  ret i32 %value
}

define i32 @policy_veto(i32 %value) {
entry:
  %buffer = alloca [257 x i8], align 1
  ret i32 %value
}

; Function Attrs: noinline
define i32 @explicit_noinline(i32 %value) #2 {
entry:
  %buffer = alloca [257 x i8], align 1
  ret i32 %value
}

attributes #0 = { alwaysinline }
attributes #1 = { alwaysinline "capsule.heap-accessor" }
attributes #2 = { noinline }
