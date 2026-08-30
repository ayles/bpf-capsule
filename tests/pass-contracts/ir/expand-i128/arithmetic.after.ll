source_filename = "expand-i128.ll"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpfel"

%words = type { i64, i64 }

; Function Attrs: nocallback nocreateundeforpoison nofree nosync nounwind speculatable willreturn memory(none)
declare { i64, i1 } @llvm.umul.with.overflow.i64(i64, i64) #0

; Function Attrs: nocallback nocreateundeforpoison nofree nosync nounwind speculatable willreturn memory(none)
declare { i64, i1 } @llvm.smul.with.overflow.i64(i64, i64) #0

define %words @__bpf_mul128(i64 %a0, i64 %a1, i64 %b0, i64 %b1) {
entry:
  ret %words zeroinitializer
}

define %words @__bpf_udiv128(i64 %a0, i64 %a1, i64 %b0, i64 %b1) {
entry:
  ret %words zeroinitializer
}

define %words @__bpf_urem128(i64 %a0, i64 %a1, i64 %b0, i64 %b1) {
entry:
  ret %words zeroinitializer
}

define %words @__bpf_sdiv128(i64 %a0, i64 %a1, i64 %b0, i64 %b1) {
entry:
  ret %words zeroinitializer
}

define %words @__bpf_srem128(i64 %a0, i64 %a1, i64 %b0, i64 %b1) {
entry:
  ret %words zeroinitializer
}

define %words @__bpf_umul64_overflow(i64 %lhs, i64 %rhs) {
entry:
  ret %words zeroinitializer
}

define %words @__bpf_smul64_overflow(i64 %lhs, i64 %rhs) {
entry:
  ret %words zeroinitializer
}

define i128 @arithmetic(i128 %lhs, i128 %rhs) {
entry:
  %0 = trunc i128 %lhs to i64
  %1 = lshr i128 %lhs, 64
  %2 = trunc i128 %1 to i64
  %3 = trunc i128 %rhs to i64
  %4 = lshr i128 %rhs, 64
  %5 = trunc i128 %4 to i64
  %6 = call %words @__bpf_mul128(i64 %0, i64 %2, i64 %3, i64 %5)
  %7 = extractvalue %words %6, 0
  %8 = extractvalue %words %6, 1
  %9 = zext i64 %7 to i128
  %10 = zext i64 %8 to i128
  %11 = shl i128 %10, 64
  %12 = or i128 %9, %11
  %13 = trunc i128 %lhs to i64
  %14 = lshr i128 %lhs, 64
  %15 = trunc i128 %14 to i64
  %16 = trunc i128 %rhs to i64
  %17 = lshr i128 %rhs, 64
  %18 = trunc i128 %17 to i64
  %19 = call %words @__bpf_udiv128(i64 %13, i64 %15, i64 %16, i64 %18)
  %20 = extractvalue %words %19, 0
  %21 = extractvalue %words %19, 1
  %22 = zext i64 %20 to i128
  %23 = zext i64 %21 to i128
  %24 = shl i128 %23, 64
  %25 = or i128 %22, %24
  %26 = trunc i128 %lhs to i64
  %27 = lshr i128 %lhs, 64
  %28 = trunc i128 %27 to i64
  %29 = trunc i128 %rhs to i64
  %30 = lshr i128 %rhs, 64
  %31 = trunc i128 %30 to i64
  %32 = call %words @__bpf_urem128(i64 %26, i64 %28, i64 %29, i64 %31)
  %33 = extractvalue %words %32, 0
  %34 = extractvalue %words %32, 1
  %35 = zext i64 %33 to i128
  %36 = zext i64 %34 to i128
  %37 = shl i128 %36, 64
  %38 = or i128 %35, %37
  %39 = trunc i128 %lhs to i64
  %40 = lshr i128 %lhs, 64
  %41 = trunc i128 %40 to i64
  %42 = trunc i128 %rhs to i64
  %43 = lshr i128 %rhs, 64
  %44 = trunc i128 %43 to i64
  %45 = call %words @__bpf_sdiv128(i64 %39, i64 %41, i64 %42, i64 %44)
  %46 = extractvalue %words %45, 0
  %47 = extractvalue %words %45, 1
  %48 = zext i64 %46 to i128
  %49 = zext i64 %47 to i128
  %50 = shl i128 %49, 64
  %51 = or i128 %48, %50
  %52 = trunc i128 %lhs to i64
  %53 = lshr i128 %lhs, 64
  %54 = trunc i128 %53 to i64
  %55 = trunc i128 %rhs to i64
  %56 = lshr i128 %rhs, 64
  %57 = trunc i128 %56 to i64
  %58 = call %words @__bpf_srem128(i64 %52, i64 %54, i64 %55, i64 %57)
  %59 = extractvalue %words %58, 0
  %60 = extractvalue %words %58, 1
  %61 = zext i64 %59 to i128
  %62 = zext i64 %60 to i128
  %63 = shl i128 %62, 64
  %64 = or i128 %61, %63
  %a = add i128 %12, %25
  %b = add i128 %38, %51
  %c = add i128 %a, %b
  %result = add i128 %c, %64
  ret i128 %result
}

define i64 @overflow(i64 %lhs, i64 %rhs) {
entry:
  %0 = call %words @__bpf_umul64_overflow(i64 %lhs, i64 %rhs)
  %1 = extractvalue %words %0, 0
  %2 = extractvalue %words %0, 1
  %3 = insertvalue { i64, i1 } poison, i64 %1, 0
  %4 = icmp ne i64 %2, 0
  %5 = insertvalue { i64, i1 } %3, i1 %4, 1
  %6 = call %words @__bpf_smul64_overflow(i64 %lhs, i64 %rhs)
  %7 = extractvalue %words %6, 0
  %8 = extractvalue %words %6, 1
  %9 = insertvalue { i64, i1 } poison, i64 %7, 0
  %10 = icmp ne i64 %8, 0
  %11 = insertvalue { i64, i1 } %9, i1 %10, 1
  %unsigned.value = extractvalue { i64, i1 } %5, 0
  %signed.value = extractvalue { i64, i1 } %11, 0
  %result = add i64 %unsigned.value, %signed.value
  ret i64 %result
}

attributes #0 = { nocallback nocreateundeforpoison nofree nosync nounwind speculatable willreturn memory(none) }
