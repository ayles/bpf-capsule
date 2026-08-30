source_filename = "lower-capsule-call.ll"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpfel"

%fiber = type { i32, i32, i64, i64, i64, i32, i32 }

@bpf_capsule_fibers = global [4 x %fiber] zeroinitializer

declare i32 @__bpf_capsule_call(i32, ptr, i64, i64, ptr, ...)

define i64 @scalar_root(ptr %context, i32 %value) {
entry:
  %context.bits = ptrtoint ptr %context to i64
  %value.wide = zext i32 %value to i64
  %result = add i64 %context.bits, %value.wide
  ret i64 %result
}

define void @void_root() {
entry:
  ret void
}

define i32 @call_scalar(ptr %context, i32 %fiber.index, i16 %value) section "xdp" {
entry:
  %output = alloca i64, align 8
  %status = call i32 (i32, ptr, i64, i64, ptr, ...) @__bpf_capsule_call(i32 %fiber.index, ptr %output, i64 8, i64 8, ptr @scalar_root, ptr %context, i16 %value)
  ret i32 %status
}

define i32 @call_void(i32 %fiber.index) section "xdp" {
entry:
  %status = call i32 (i32, ptr, i64, i64, ptr, ...) @__bpf_capsule_call(i32 %fiber.index, ptr null, i64 0, i64 1, ptr @void_root)
  ret i32 %status
}
