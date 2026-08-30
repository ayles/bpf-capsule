source_filename = "expand-memmove.ll"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpfel"

define void @move(ptr %destination, ptr %source, i64 %length) {
entry:
  call void @llvm.memmove.p0.p0.i64(ptr align 1 %destination, ptr align 1 %source, i64 %length, i1 false)
  ret void
}

; Function Attrs: nocallback nofree nosync nounwind willreturn memory(argmem: readwrite)
declare void @llvm.memmove.p0.p0.i64(ptr writeonly captures(none), ptr readonly captures(none), i64, i1 immarg) #0

attributes #0 = { nocallback nofree nosync nounwind willreturn memory(argmem: readwrite) }
