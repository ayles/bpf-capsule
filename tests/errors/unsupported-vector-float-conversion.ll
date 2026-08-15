; SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

define void @unsupported_vector_float_conversion() {
entry:
  %value = sitofp <2 x i64> <i64 1, i64 2> to <2 x double>
  ret void
}
