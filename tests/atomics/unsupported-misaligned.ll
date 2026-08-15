; SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
target triple = "bpf"

@word = internal global i32 0, align 4

define void @unsupported_misaligned() !bpf.capsule !0 {
entry:
  %value = load atomic i32, ptr @word monotonic, align 1
  ret void
}

!0 = !{}
