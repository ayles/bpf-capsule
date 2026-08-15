; SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
target triple = "bpf"

declare void @llvm.va_start(ptr)
declare void @llvm.va_end(ptr)

define i64 @take_value(i32 %fixed, ...) {
entry:
  %list = alloca ptr, align 8
  call void @llvm.va_start(ptr %list)
  %value = va_arg ptr %list, i64
  call void @llvm.va_end(ptr %list)
  ret i64 %value
}

define i64 @call_value() {
entry:
  %value = call i64 (i32, ...) @take_value(i32 0, i64 42)
  ret i64 %value
}
