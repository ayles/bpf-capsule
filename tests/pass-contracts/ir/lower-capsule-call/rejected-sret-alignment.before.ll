source_filename = "lower-capsule-call-rejected-sret-alignment.ll"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpfel"

%fiber = type { i32, i32, i64, i64, i64, i32, i32 }

@bpf_capsule_fibers = global [1 x %fiber] zeroinitializer

declare i32 @__bpf_capsule_call(i32, ptr, ptr, i64, i64, ptr, ...)

define void @bytes_root(ptr sret([40 x i8]) align 8 %output) {
entry:
  store [40 x i8] zeroinitializer, ptr %output, align 8
  ret void
}

define i32 @call_bytes() section "xdp" {
entry:
  %output = alloca [40 x i8], align 1
  %status = call i32 (i32, ptr, ptr, i64, i64, ptr, ...) @__bpf_capsule_call(i32 0, ptr null, ptr %output, i64 40, i64 1, ptr @bytes_root)
  ret i32 %status
}
