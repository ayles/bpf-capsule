; SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

define void @unsupported_wide_float() {
entry:
  %value = fadd fp128 undef, undef
  ret void
}
