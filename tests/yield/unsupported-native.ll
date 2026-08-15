; SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
target triple = "bpf"

declare void @__bpf_capsule_yield()

define i32 @native_yield() section "xdp" {
entry:
  call void @__bpf_capsule_yield()
  ret i32 2
}
