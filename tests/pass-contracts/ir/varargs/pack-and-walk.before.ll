source_filename = "varargs.ll"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpfel"

define i64 @sum_slots(i32 %fixed, ...) {
entry:
  %list = alloca ptr, align 8
  call void @llvm.va_start.p0(ptr %list)
  %first = va_arg ptr %list, i32
  %second = va_arg ptr %list, i64
  %third = va_arg ptr %list, ptr
  call void @llvm.va_end.p0(ptr %list)
  %third.bits = ptrtoint ptr %third to i64
  %first.wide = zext i32 %first to i64
  %a = add i64 %first.wide, %second
  %b = add i64 %a, %third.bits
  %fixed.wide = zext i32 %fixed to i64
  %result = add i64 %b, %fixed.wide
  ret i64 %result
}

define i32 @take_next(ptr %list) {
entry:
  %value = va_arg ptr %list, i32
  ret i32 %value
}

define i64 @caller(ptr %pointer) {
entry:
  %result = call i64 (i32, ...) @sum_slots(i32 4, i32 5, i64 6, ptr %pointer)
  ret i64 %result
}

; Function Attrs: nocallback nofree nosync nounwind willreturn
declare void @llvm.va_start.p0(ptr) #0

; Function Attrs: nocallback nofree nosync nounwind willreturn
declare void @llvm.va_end.p0(ptr) #0

attributes #0 = { nocallback nofree nosync nounwind willreturn }
