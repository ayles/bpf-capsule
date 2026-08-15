; SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
target triple = "bpf"

@word = internal global i32 0, align 4

define void @unsupported_order() !bpf.capsule !0 {
entry:
  %value = load atomic i32, ptr @word acquire, align 4
  ret void
}

!0 = !{}
