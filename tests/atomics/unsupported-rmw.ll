; SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
target triple = "bpf"

@counter = internal global i8 0, align 1

define void @unsupported_rmw() !bpf.capsule !0 {
entry:
  %old = atomicrmw add ptr @counter, i8 1 seq_cst, align 1
  ret void
}

!0 = !{}
