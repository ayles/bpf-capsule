; SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

define i128 @unsupported_wide_float_conversion_result(double %value) {
entry:
  %converted = fptosi double %value to i128
  ret i128 %converted
}
