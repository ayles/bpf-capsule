source_filename = "lower-capsule-call-rejected-target.ll"
target triple = "bpfel"

%fiber = type { i32, i32, i64, i64, i64, i32, i32 }

@bpf_capsule_fibers = global [1 x %fiber] zeroinitializer

declare i32 @__bpf_capsule_call(i32, ptr, i64, i64, ptr, ...)

declare void @declared_root()

define i32 @entry() {
entry:
  %status = call i32 (i32, ptr, i64, i64, ptr, ...) @__bpf_capsule_call(i32 0, ptr null, i64 0, i64 1, ptr @declared_root)
  ret i32 %status
}
