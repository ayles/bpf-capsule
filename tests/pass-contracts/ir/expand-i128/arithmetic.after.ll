source_filename = "expand-i128.ll"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpfel"

; Function Attrs: nocallback nocreateundeforpoison nofree nosync nounwind speculatable willreturn memory(none)
declare { i64, i1 } @llvm.umul.with.overflow.i64(i64, i64) #0

; Function Attrs: nocallback nocreateundeforpoison nofree nosync nounwind speculatable willreturn memory(none)
declare { i64, i1 } @llvm.smul.with.overflow.i64(i64, i64) #0

define i128 @arithmetic(i128 %lhs, i128 %rhs) {
entry:
  %0 = call i128 @__multi3(i128 %lhs, i128 %rhs)
  %1 = call i128 @__udivti3(i128 %lhs, i128 %rhs)
  %2 = call i128 @__umodti3(i128 %lhs, i128 %rhs)
  %3 = call i128 @__divti3(i128 %lhs, i128 %rhs)
  %4 = call i128 @__modti3(i128 %lhs, i128 %rhs)
  %a = add i128 %0, %1
  %b = add i128 %2, %3
  %c = add i128 %a, %b
  %result = add i128 %c, %4
  ret i128 %result
}

define i64 @overflow(i64 %lhs, i64 %rhs) {
entry:
  %multiply.overflow = alloca i32, align 4
  %0 = zext i64 %lhs to i128
  %1 = zext i64 %rhs to i128
  %2 = call i128 @__multi3(i128 %0, i128 %1)
  %3 = trunc i128 %2 to i64
  %4 = lshr i128 %2, 64
  %5 = icmp ne i128 %4, 0
  %6 = insertvalue { i64, i1 } poison, i64 %3, 0
  %7 = insertvalue { i64, i1 } %6, i1 %5, 1
  %8 = call i64 @__mulodi4(i64 %lhs, i64 %rhs, ptr %multiply.overflow)
  %9 = load i32, ptr %multiply.overflow, align 4
  %10 = icmp ne i32 %9, 0
  %11 = insertvalue { i64, i1 } poison, i64 %8, 0
  %12 = insertvalue { i64, i1 } %11, i1 %10, 1
  %unsigned.value = extractvalue { i64, i1 } %7, 0
  %signed.value = extractvalue { i64, i1 } %12, 0
  %result = add i64 %unsigned.value, %signed.value
  ret i64 %result
}

declare i128 @__multi3(i128, i128)

declare i128 @__udivti3(i128, i128)

declare i128 @__umodti3(i128, i128)

declare i128 @__divti3(i128, i128)

declare i128 @__modti3(i128, i128)

declare i64 @__mulodi4(i64, i64, ptr)

attributes #0 = { nocallback nocreateundeforpoison nofree nosync nounwind speculatable willreturn memory(none) }
