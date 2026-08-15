; SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

define void @unsupported_vector_float() {
entry:
  %value = fadd <2 x float> zeroinitializer, zeroinitializer
  ret void
}
