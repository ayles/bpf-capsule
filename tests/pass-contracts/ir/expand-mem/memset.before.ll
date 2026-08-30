source_filename = "expand-memset.ll"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpfel"

define void @fill(ptr %destination, i8 %byte, i64 %length) {
entry:
  call void @llvm.memset.p0.i64(ptr align 1 %destination, i8 %byte, i64 %length, i1 true)
  ret void
}

; Function Attrs: nocallback nofree nosync nounwind willreturn memory(argmem: write)
declare void @llvm.memset.p0.i64(ptr writeonly captures(none), i8, i64, i1 immarg) #0

attributes #0 = { nocallback nofree nosync nounwind willreturn memory(argmem: write) }
