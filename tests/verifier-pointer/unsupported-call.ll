; SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
target triple = "bpf"

%fiber.control = type { i64, i64, i64, i64 }
%object.config = type { i64, i64, i64, i64, i32, i32, i32, i32, i32, i32, i32, i32 }
@bpf_capsule_fibers = global [1 x %fiber.control] zeroinitializer, section ".bss.bpfctrl", align 8
@bpf_capsule_config = constant %object.config { i64 0, i64 0, i64 0, i64 0, i32 1, i32 262144, i32 1, i32 0, i32 0, i32 0, i32 0, i32 0 }, section ".rodata.bpfconfig", align 8

define void @suspendable_callee(i64 %value) !bpf.capsule !0 {
entry:
  ret void
}

define i64 @pointer_across_call(ptr %key) !bpf.capsule !0 {
entry:
  %map.value = call ptr inttoptr (i64 1 to ptr)(ptr null, ptr %key)
  %before = load i64, ptr %map.value, align 8
  call void @suspendable_callee(i64 %before)
  %after = load i64, ptr %map.value, align 8
  ret i64 %after
}

!0 = !{}
