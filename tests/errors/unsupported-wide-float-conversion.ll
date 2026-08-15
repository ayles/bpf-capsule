; SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

define double @unsupported_wide_float_conversion(i128 %value) {
entry:
  %converted = sitofp i128 %value to double
  ret double %converted
}
