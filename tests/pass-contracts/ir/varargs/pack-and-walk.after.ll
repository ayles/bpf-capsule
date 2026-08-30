source_filename = "varargs.ll"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpfel"

define i32 @take_next(ptr %list) {
entry:
  %0 = load ptr, ptr %list, align 8
  %1 = load i32, ptr %0, align 4
  %2 = getelementptr i8, ptr %0, i64 8
  store ptr %2, ptr %list, align 8
  ret i32 %1
}

define i64 @caller(ptr %pointer) {
entry:
  %vararg.buffer = alloca [24 x i8], align 8
  %0 = getelementptr i8, ptr %vararg.buffer, i64 0
  store i32 5, ptr %0, align 4
  %1 = getelementptr i8, ptr %vararg.buffer, i64 8
  store i64 6, ptr %1, align 8
  %2 = getelementptr i8, ptr %vararg.buffer, i64 16
  store ptr %pointer, ptr %2, align 8
  %3 = call i64 @sum_slots(i32 4, ptr %vararg.buffer)
  ret i64 %3
}

; Function Attrs: nocallback nofree nosync nounwind willreturn
declare void @llvm.va_start.p0(ptr) #0

; Function Attrs: nocallback nofree nosync nounwind willreturn
declare void @llvm.va_end.p0(ptr) #0

define i64 @sum_slots(i32 %fixed, ptr %vararg.pack) {
entry:
  %list = alloca ptr, align 8
  store ptr %vararg.pack, ptr %list, align 8
  %0 = load ptr, ptr %list, align 8
  %1 = load i32, ptr %0, align 4
  %2 = getelementptr i8, ptr %0, i64 8
  store ptr %2, ptr %list, align 8
  %3 = load ptr, ptr %list, align 8
  %4 = load i64, ptr %3, align 8
  %5 = getelementptr i8, ptr %3, i64 8
  store ptr %5, ptr %list, align 8
  %6 = load ptr, ptr %list, align 8
  %7 = load ptr, ptr %6, align 8
  %8 = getelementptr i8, ptr %6, i64 8
  store ptr %8, ptr %list, align 8
  %third.bits = ptrtoint ptr %7 to i64
  %first.wide = zext i32 %1 to i64
  %a = add i64 %first.wide, %4
  %b = add i64 %a, %third.bits
  %fixed.wide = zext i32 %fixed to i64
  %result = add i64 %b, %fixed.wide
  ret i64 %result
}

attributes #0 = { nocallback nofree nosync nounwind willreturn }
