; SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
target triple = "bpf"

define void @unsupported_fence() !bpf.capsule !0 {
entry:
  fence seq_cst
  ret void
}

!0 = !{}
