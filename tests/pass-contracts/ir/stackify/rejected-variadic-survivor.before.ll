source_filename = "stackify-rejected-variadic-survivor.ll"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpfel"

define void @variadic_root(i32 %fixed, ...) !bpf.capsule !0 {
entry:
  ret void
}

define i32 @start(i32 %fiber) section "syscall" !bpf.native !0 {
entry:
  call void (i32, ...) @variadic_root(i32 7) [ "bpf.capsule.call"(i32 %fiber) ]
  ret i32 0
}

!0 = !{}
