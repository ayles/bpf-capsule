source_filename = "expand-memcpy.ll"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpfel"

define void @copy(ptr %destination, ptr %source, i32 %length) {
entry:
  %0 = zext i32 %length to i64
  %1 = udiv i64 %0, 8
  %2 = mul i64 %1, 8
  br label %copy.cond

copy.cond:                                        ; preds = %copy.body, %entry
  %copy.i = phi i64 [ 0, %entry ], [ %7, %copy.body ]
  %3 = icmp ult i64 %copy.i, %2
  br i1 %3, label %copy.body, label %copy.after

copy.body:                                        ; preds = %copy.cond
  %4 = getelementptr i8, ptr %source, i64 %copy.i
  %5 = load i64, ptr %4, align 1
  %6 = getelementptr i8, ptr %destination, i64 %copy.i
  store i64 %5, ptr %6, align 1
  %7 = add i64 %copy.i, 8
  br label %copy.cond

copy.after:                                       ; preds = %copy.cond
  br label %copy.cond2

copy.cond2:                                       ; preds = %copy.body3, %copy.after
  %copy.i4 = phi i64 [ %2, %copy.after ], [ %12, %copy.body3 ]
  %8 = icmp ult i64 %copy.i4, %0
  br i1 %8, label %copy.body3, label %copy.after1

copy.body3:                                       ; preds = %copy.cond2
  %9 = getelementptr i8, ptr %source, i64 %copy.i4
  %10 = load i8, ptr %9, align 1
  %11 = getelementptr i8, ptr %destination, i64 %copy.i4
  store i8 %10, ptr %11, align 1
  %12 = add i64 %copy.i4, 1
  br label %copy.cond2

copy.after1:                                      ; preds = %copy.cond2
  ret void
}

; Function Attrs: nocallback nofree nosync nounwind willreturn memory(argmem: readwrite)
declare void @llvm.memcpy.p0.p0.i32(ptr noalias writeonly captures(none), ptr noalias readonly captures(none), i32, i1 immarg) #0

attributes #0 = { nocallback nofree nosync nounwind willreturn memory(argmem: readwrite) }
