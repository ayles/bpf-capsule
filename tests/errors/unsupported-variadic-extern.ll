; SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
target triple = "bpf"

declare i32 @external_log(i32, ...)

define i32 @caller(i32 %value) {
entry:
  %result = call i32 (i32, ...) @external_log(i32 1, i32 %value)
  ret i32 %result
}
