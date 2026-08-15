; SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
target triple = "bpf"

@word = internal global i32 0, align 4

define void @unsupported_cmpxchg() !bpf.capsule !0 {
entry:
  %pair = cmpxchg ptr @word, i32 0, i32 1 seq_cst seq_cst, align 4
  ret void
}

!0 = !{}
