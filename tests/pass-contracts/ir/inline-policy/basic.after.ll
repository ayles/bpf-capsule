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

define i32 @plain(i32 %value) #2 {
entry:
  ret i32 %value
}

; Function Attrs: noinline
define i32 @policy_veto(i32 %value) #3 {
entry:
  %buffer = alloca [257 x i8], align 1
  ret i32 %value
}

; Function Attrs: noinline
define i32 @explicit_noinline(i32 %value) #4 {
entry:
  %buffer = alloca [257 x i8], align 1
  ret i32 %value
}

attributes #0 = { alwaysinline "no-builtins" }
attributes #1 = { alwaysinline "capsule.heap-accessor" "no-builtins" }
attributes #2 = { "no-builtins" }
attributes #3 = { noinline "bpf.capsule.inline-policy-veto" "no-builtins" }
attributes #4 = { noinline "no-builtins" }

!llvm.module.flags = !{!0}

!0 = !{i32 1, !"bpf.capsule.classes", i32 1}
