source_filename = "lower-arena-sext.ll"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpfel"

define i64 @loads(ptr addrspace(1) %arena, ptr %native) {
entry:
  %arena8 = load i8, ptr addrspace(1) %arena, align 1
  %arena16.pointer = getelementptr i8, ptr addrspace(1) %arena, i64 2
  %arena16 = load i16, ptr addrspace(1) %arena16.pointer, align 2
  %arena32.pointer = getelementptr i8, ptr addrspace(1) %arena, i64 4
  %arena32 = load i32, ptr addrspace(1) %arena32.pointer, align 4
  %arena64.pointer = getelementptr i8, ptr addrspace(1) %arena, i64 8
  %arena64 = load i64, ptr addrspace(1) %arena64.pointer, align 8
  %native8 = load i8, ptr %native, align 1
  %a = sext i8 %arena8 to i64
  %b = sext i16 %arena16 to i64
  %c = sext i32 %arena32 to i64
  %d = sext i8 %native8 to i64
  %ab = add i64 %a, %b
  %cd = add i64 %c, %d
  %abcd = add i64 %ab, %cd
  %result = add i64 %abcd, %arena64
  ret i64 %result
}
