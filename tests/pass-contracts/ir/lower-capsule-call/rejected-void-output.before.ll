source_filename = "lower-capsule-call-rejected-void-output.ll"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpfel"

%fiber = type { i32, i32, i64, i64, i64, i32, i32 }

@bpf_capsule_fibers = global [1 x %fiber] zeroinitializer

declare i32 @__bpf_capsule_call(i32, ptr, i64, i64, ptr, ...)

define void @root() {
entry:
  ret void
}

define i32 @entry() {
entry:
  %output = alloca i32, align 4
  %status = call i32 (i32, ptr, i64, i64, ptr, ...) @__bpf_capsule_call(i32 0, ptr %output, i64 0, i64 1, ptr @root)
  ret i32 %status
}
