; SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
target triple = "bpf"

%fiber.control = type { i64, i64, i64, i64 }
%object.config = type { i64, i64, i64, i64, i32, i32, i32, i32, i32, i32, i32, i32 }
%control = type { i64, i64 }
@bpf_capsule_fibers = global [1 x %fiber.control] zeroinitializer, section ".bss.bpfctrl", align 8
@bpf_capsule_config = constant %object.config { i64 0, i64 0, i64 0, i64 0, i32 1, i32 262144, i32 1, i32 0, i32 0, i32 0, i32 0, i32 0 }, section ".rodata.bpfconfig", align 8
@sectioned_control = global %control zeroinitializer, section ".data.control", align 8

define void @suspendable_callee(ptr %output) !bpf.capsule !0 {
entry:
  store i64 42, ptr %output, align 8
  ret void
}

define void @sectioned_global_pointer_across_call() !bpf.capsule !0 {
entry:
  %output = getelementptr inbounds %control, ptr @sectioned_control, i32 0, i32 1
  call void @suspendable_callee(ptr %output)
  ret void
}

!0 = !{}
