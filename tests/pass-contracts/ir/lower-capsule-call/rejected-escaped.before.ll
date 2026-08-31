source_filename = "lower-capsule-call-rejected-escaped.ll"
target triple = "bpfel"

@saved_marker = global ptr @__bpf_capsule_call

declare i32 @__bpf_capsule_call(i32, ptr, ptr, i64, i64, ptr, ...)
