source_filename = "stackify-native-verifier-varargs.ll"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpfel"

@format = private constant [3 x i8] c"%d\00", section ".rodata"

declare void @native_report(ptr, i32, ...) section ".ksyms"

define i64 @native_calls(i32 %value) section "syscall" !bpf.native !1 {
entry:
  call void (ptr, i32, ...) @native_report(ptr @format, i32 3, i32 %value)
  %result = call i64 (ptr, i32, ...) inttoptr (i64 6 to ptr)(ptr @format, i32 3, i32 %value)
  ret i64 %result
}

!llvm.module.flags = !{!0}

!0 = !{i32 1, !"bpf.capsule.classes", i32 1}
!1 = !{}
