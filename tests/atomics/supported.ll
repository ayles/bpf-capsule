; SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
target triple = "bpf"

@value8 = internal global i8 0, align 1
@value16 = internal global i16 0, align 2
@value32 = internal global i32 0, align 4
@value64 = internal global i64 0, align 8

define void @supported_relaxed_load_store() !bpf.capsule !0 {
entry:
  %v8 = load atomic i8, ptr @value8 monotonic, align 1
  %v16 = load atomic i16, ptr @value16 monotonic, align 2
  %v32 = load atomic i32, ptr @value32 monotonic, align 4
  %v64 = load atomic i64, ptr @value64 monotonic, align 8
  store atomic i8 %v8, ptr @value8 unordered, align 1
  store atomic i16 %v16, ptr @value16 monotonic, align 2
  store atomic i32 %v32, ptr @value32 monotonic, align 4
  store atomic i64 %v64, ptr @value64 monotonic, align 8
  ret void
}

!0 = !{}
