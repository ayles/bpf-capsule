; SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
target triple = "bpf"

declare void @__bpf_capsule_exit(i32)

@escaped_exit = global ptr @__bpf_capsule_exit
