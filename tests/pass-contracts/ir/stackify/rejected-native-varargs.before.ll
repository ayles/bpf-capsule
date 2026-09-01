source_filename = "stackify-rejected-native-varargs.ll"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpfel"

define i32 @native_varargs(i32 %fixed, ...) section "xdp" {
entry:
  %list = alloca ptr, align 8
  call void @llvm.va_start.p0(ptr %list)
  %value = va_arg ptr %list, i32
  call void @llvm.va_end.p0(ptr %list)
  ret i32 %value
}

; Function Attrs: nocallback nofree nosync nounwind willreturn
declare void @llvm.va_start.p0(ptr) #0

; Function Attrs: nocallback nofree nosync nounwind willreturn
declare void @llvm.va_end.p0(ptr) #0

attributes #0 = { nocallback nofree nosync nounwind willreturn }
