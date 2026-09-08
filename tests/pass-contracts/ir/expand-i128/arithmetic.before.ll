source_filename = "expand-i128.ll"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpfel"

; Function Attrs: nocallback nocreateundeforpoison nofree nosync nounwind speculatable willreturn memory(none)
declare { i64, i1 } @llvm.umul.with.overflow.i64(i64, i64) #0

; Function Attrs: nocallback nocreateundeforpoison nofree nosync nounwind speculatable willreturn memory(none)
declare { i64, i1 } @llvm.smul.with.overflow.i64(i64, i64) #0

define i128 @arithmetic(i128 %lhs, i128 %rhs) {
entry:
  %mul = mul i128 %lhs, %rhs
  %udiv = udiv i128 %lhs, %rhs
  %urem = urem i128 %lhs, %rhs
  %sdiv = sdiv i128 %lhs, %rhs
  %srem = srem i128 %lhs, %rhs
  %a = add i128 %mul, %udiv
  %b = add i128 %urem, %sdiv
  %c = add i128 %a, %b
  %result = add i128 %c, %srem
  ret i128 %result
}

define i64 @overflow(i64 %lhs, i64 %rhs) {
entry:
  %unsigned = call { i64, i1 } @llvm.umul.with.overflow.i64(i64 %lhs, i64 %rhs)
  %signed = call { i64, i1 } @llvm.smul.with.overflow.i64(i64 %lhs, i64 %rhs)
  %unsigned.value = extractvalue { i64, i1 } %unsigned, 0
  %signed.value = extractvalue { i64, i1 } %signed, 0
  %result = add i64 %unsigned.value, %signed.value
  ret i64 %result
}

attributes #0 = { nocallback nocreateundeforpoison nofree nosync nounwind speculatable willreturn memory(none) }
