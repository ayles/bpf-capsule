source_filename = "expand-memset.ll"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpfel"

define void @fill(ptr %destination, i8 %byte, i64 %length) {
entry:
  %0 = zext i8 %byte to i64
  %1 = mul i64 %0, 72340172838076673
  %2 = udiv i64 %length, 8
  %3 = mul i64 %2, 8
  br label %set.cond

set.cond:                                         ; preds = %set.body, %entry
  %set.i = phi i64 [ 0, %entry ], [ %6, %set.body ]
  %4 = icmp ult i64 %set.i, %3
  br i1 %4, label %set.body, label %set.after

set.body:                                         ; preds = %set.cond
  %5 = getelementptr i8, ptr %destination, i64 %set.i
  store volatile i64 %1, ptr %5, align 1
  %6 = add i64 %set.i, 8
  br label %set.cond

set.after:                                        ; preds = %set.cond
  br label %set.cond2

set.cond2:                                        ; preds = %set.body3, %set.after
  %set.i4 = phi i64 [ %3, %set.after ], [ %9, %set.body3 ]
  %7 = icmp ult i64 %set.i4, %length
  br i1 %7, label %set.body3, label %set.after1

set.body3:                                        ; preds = %set.cond2
  %8 = getelementptr i8, ptr %destination, i64 %set.i4
  store volatile i8 %byte, ptr %8, align 1
  %9 = add i64 %set.i4, 1
  br label %set.cond2

set.after1:                                       ; preds = %set.cond2
  ret void
}

; Function Attrs: nocallback nofree nosync nounwind willreturn memory(argmem: write)
declare void @llvm.memset.p0.i64(ptr writeonly captures(none), i8, i64, i1 immarg) #0

attributes #0 = { nocallback nofree nosync nounwind willreturn memory(argmem: write) }
