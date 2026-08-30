source_filename = "expand-memmove.ll"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpfel"

define void @move(ptr %destination, ptr %source, i64 %length) {
entry:
  %0 = ptrtoint ptr %destination to i64
  %1 = ptrtoint ptr %source to i64
  %2 = icmp ugt i64 %0, %1
  br i1 %2, label %3, label %16

3:                                                ; preds = %entry
  %4 = udiv i64 %length, 8
  %5 = mul i64 %4, 8
  br label %copy.cond

copy.cond:                                        ; preds = %copy.body, %3
  %copy.i = phi i64 [ %length, %3 ], [ %7, %copy.body ]
  %6 = icmp ugt i64 %copy.i, %5
  br i1 %6, label %copy.body, label %copy.after

copy.body:                                        ; preds = %copy.cond
  %7 = sub i64 %copy.i, 1
  %8 = getelementptr i8, ptr %source, i64 %7
  %9 = load i8, ptr %8, align 1
  %10 = getelementptr i8, ptr %destination, i64 %7
  store i8 %9, ptr %10, align 1
  br label %copy.cond

copy.after:                                       ; preds = %copy.cond
  br label %copy.cond2

copy.cond2:                                       ; preds = %copy.body3, %copy.after
  %copy.i4 = phi i64 [ %5, %copy.after ], [ %12, %copy.body3 ]
  %11 = icmp ugt i64 %copy.i4, 0
  br i1 %11, label %copy.body3, label %copy.after1

copy.body3:                                       ; preds = %copy.cond2
  %12 = sub i64 %copy.i4, 8
  %13 = getelementptr i8, ptr %source, i64 %12
  %14 = load i64, ptr %13, align 1
  %15 = getelementptr i8, ptr %destination, i64 %12
  store i64 %14, ptr %15, align 1
  br label %copy.cond2

copy.after1:                                      ; preds = %copy.cond2
  br label %29

16:                                               ; preds = %entry
  %17 = udiv i64 %length, 8
  %18 = mul i64 %17, 8
  br label %copy.cond6

copy.cond6:                                       ; preds = %copy.body7, %16
  %copy.i8 = phi i64 [ 0, %16 ], [ %23, %copy.body7 ]
  %19 = icmp ult i64 %copy.i8, %18
  br i1 %19, label %copy.body7, label %copy.after5

copy.body7:                                       ; preds = %copy.cond6
  %20 = getelementptr i8, ptr %source, i64 %copy.i8
  %21 = load i64, ptr %20, align 1
  %22 = getelementptr i8, ptr %destination, i64 %copy.i8
  store i64 %21, ptr %22, align 1
  %23 = add i64 %copy.i8, 8
  br label %copy.cond6

copy.after5:                                      ; preds = %copy.cond6
  br label %copy.cond10

copy.cond10:                                      ; preds = %copy.body11, %copy.after5
  %copy.i12 = phi i64 [ %18, %copy.after5 ], [ %28, %copy.body11 ]
  %24 = icmp ult i64 %copy.i12, %length
  br i1 %24, label %copy.body11, label %copy.after9

copy.body11:                                      ; preds = %copy.cond10
  %25 = getelementptr i8, ptr %source, i64 %copy.i12
  %26 = load i8, ptr %25, align 1
  %27 = getelementptr i8, ptr %destination, i64 %copy.i12
  store i8 %26, ptr %27, align 1
  %28 = add i64 %copy.i12, 1
  br label %copy.cond10

copy.after9:                                      ; preds = %copy.cond10
  br label %29

29:                                               ; preds = %copy.after9, %copy.after1
  ret void
}

; Function Attrs: nocallback nofree nosync nounwind willreturn memory(argmem: readwrite)
declare void @llvm.memmove.p0.p0.i64(ptr writeonly captures(none), ptr readonly captures(none), i64, i1 immarg) #0

attributes #0 = { nocallback nofree nosync nounwind willreturn memory(argmem: readwrite) }
