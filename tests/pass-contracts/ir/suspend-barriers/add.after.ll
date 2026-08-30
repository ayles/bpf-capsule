source_filename = "add-suspend-barriers.ll"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpfel"

define i32 @managed(i32 %value) !bpf.capsule !0 {
entry:
  call void @__bpf_capsule_suspend_barrier()
  %result = add i32 %value, 1
  ret i32 %result
}

define i32 @native(i32 %value) !bpf.native !0 {
entry:
  ret i32 %value
}

declare void @__bpf_capsule_suspend_barrier()

!0 = !{}
