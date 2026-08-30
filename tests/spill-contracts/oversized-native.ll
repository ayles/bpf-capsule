; SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
; Passing this address to a kfunc pins the whole object to the native stack.
; An ordinary entry has no leased fiber, so relocation is never a fallback.

target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpfel"

declare i64 @stack_consumer(ptr) section ".ksyms"

define i32 @oversized_native() section "syscall" {
entry:
  %buffer = alloca [600 x i8], align 8
  %value = call i64 @stack_consumer(ptr %buffer)
  %result = trunc i64 %value to i32
  ret i32 %result
}
