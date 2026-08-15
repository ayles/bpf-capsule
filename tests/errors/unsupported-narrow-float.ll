; SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

define void @unsupported_narrow_float() {
entry:
  %value = fadd half 0.0, 0.0
  ret void
}
