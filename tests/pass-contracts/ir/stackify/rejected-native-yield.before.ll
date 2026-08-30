source_filename = "stackify-rejected-native-yield.ll"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpfel"

declare void @__bpf_capsule_yield()

define i32 @native_yield() section "xdp" {
entry:
  call void @__bpf_capsule_yield()
  ret i32 2
}
