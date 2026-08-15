; SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
target triple = "bpf"

%fiber.control = type { i64, i64, i64, i64 }
%object.config = type { i64, i64, i64, i64, i32, i32, i32, i32, i32, i32, i32, i32 }
@bpf_capsule_fibers = global [1 x %fiber.control] zeroinitializer, section ".bss.bpfctrl", align 8
@bpf_capsule_config = constant %object.config { i64 0, i64 0, i64 0, i64 0, i32 1, i32 262144, i32 1, i32 0, i32 0, i32 0, i32 0, i32 0 }, section ".rodata.bpfconfig", align 8
@dynamic_root = global ptr @dynamic_alloca

define void @dynamic_alloca(i64 %count) !bpf.capsule !0 {
entry:
  %storage = alloca i8, i64 %count, align 16
  store volatile i8 1, ptr %storage, align 16
  ret void
}

!0 = !{}
