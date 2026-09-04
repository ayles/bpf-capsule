source_filename = "linker-platform-markers.ll"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpfel"

@__bpf_capsule_memory_backend = constant i32 0
@__bpf_capsule_allocator_lock_mode = constant i32 0

define void @__bpf_capsule_fiber_acquire() {
entry:
  ret void
}
