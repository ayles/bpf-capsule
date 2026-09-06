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

; Function Attrs: noinline
define i32 @variadic(i32 %value, ...) #2 {
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
define i32 @explicit_noinline(i32 %value) #2 {
entry:
  %buffer = alloca [257 x i8], align 1
  ret i32 %value
}

; Function Attrs: alwaysinline
define void @runtime_outer_loop(ptr %counter) #4 {
entry:
  br label %loop

loop:                                             ; preds = %loop, %entry
  %value = load volatile i32, ptr %counter, align 4
  %done = icmp eq i32 %value, 0
  br i1 %done, label %exit, label %loop

exit:                                             ; preds = %loop
  ret void
}

; Function Attrs: noinline
define void @runtime_inner_loop(ptr %counter) #5 {
entry:
  br label %loop

loop:                                             ; preds = %loop, %entry
  %value = load volatile i32, ptr %counter, align 4
  %done = icmp eq i32 %value, 0
  br i1 %done, label %exit, label %loop

exit:                                             ; preds = %loop
  ret void
}

attributes #0 = { alwaysinline }
attributes #1 = { alwaysinline "capsule.heap-accessor" }
attributes #2 = { noinline }
attributes #3 = { noinline "bpf.capsule.inline-policy-veto" }
attributes #4 = { alwaysinline "capsule.trampoline" }
attributes #5 = { noinline "capsule.trampoline" }

!llvm.module.flags = !{!0}

!0 = !{i32 1, !"bpf.capsule.classes", i32 1}
