source_filename = "remove-suspend-barriers.ll"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpfel"

declare void @__bpf_capsule_suspend_barrier()

define i32 @managed(i32 %value) !bpf.capsule !0 {
entry:
  call void @__bpf_capsule_suspend_barrier()
  %result = add i32 %value, 1
  ret i32 %result
}

define void @second() !bpf.capsule !0 {
entry:
  call void @__bpf_capsule_suspend_barrier()
  ret void
}

!0 = !{}
