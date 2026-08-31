source_filename = "lower-capsule-call-rejected-argument-type.ll"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpfel"

%fiber = type { i32, i32, i64, i64, i64, i32, i32 }

@bpf_capsule_fibers = global [1 x %fiber] zeroinitializer

declare i32 @__bpf_capsule_call(i32, ptr, ptr, i64, i64, ptr, ...)

define void @root(ptr %value) {
entry:
  ret void
}

define i32 @entry(i64 %value) {
entry:
  %status = call i32 (i32, ptr, ptr, i64, i64, ptr, ...) @__bpf_capsule_call(i32 0, ptr null, ptr null, i64 0, i64 1, ptr @root, i64 %value)
  ret i32 %status
}
