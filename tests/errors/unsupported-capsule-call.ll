; SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
target triple = "bpf"

%fiber.control = type { i64, i64, i64, i64 }
%object.config = type { i64, i64, i64, i64, i32, i32, i32, i32, i32, i32, i32, i32 }
@bpf_capsule_fibers = global [1 x %fiber.control] zeroinitializer, section ".bss.bpfctrl", align 8
@bpf_capsule_config = constant %object.config { i64 0, i64 0, i64 0, i64 0, i32 1, i32 262144, i32 1, i32 0, i32 0, i32 0, i32 0, i32 0 }, section ".rodata.bpfconfig", align 8
@result = global i32 0, section ".data.result", align 4

declare i32 @__bpf_capsule_call(i32, ptr, i64, i64, ptr, ...)

define i32 @root(i32 %value) {
entry:
  ret i32 %value
}

define i32 @entry() section "syscall" {
entry:
  %status = call i32 (i32, ptr, i64, i64, ptr, ...) @__bpf_capsule_call(
      i32 0, ptr @result, i64 8, i64 4, ptr @root, i32 7)
  ret i32 %status
}
