; SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
target triple = "bpf"

declare void @llvm.va_start(ptr)
declare void @llvm.va_end(ptr)

define i128 @take_wide(i32 %fixed, ...) {
entry:
  %list = alloca ptr, align 8
  call void @llvm.va_start(ptr %list)
  %value = va_arg ptr %list, i128
  call void @llvm.va_end(ptr %list)
  ret i128 %value
}

define i128 @call_wide() {
entry:
  %value = call i128 (i32, ...) @take_wide(i32 0, i128 1)
  ret i128 %value
}
