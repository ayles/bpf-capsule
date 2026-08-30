source_filename = "expand-native-memset.ll"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpfel"

@map_value = global [64 x i8] zeroinitializer, section ".data.map"

declare ptr @memset(ptr, i32, i64)

define ptr @fill_map(i32 %value, i64 %length) {
entry:
  %0 = trunc i32 %value to i8
  %1 = zext i8 %0 to i64
  %2 = mul i64 %1, 72340172838076673
  %3 = udiv i64 %length, 8
  %4 = mul i64 %3, 8
  br label %set.cond

set.cond:                                         ; preds = %set.body, %entry
  %set.i = phi i64 [ 0, %entry ], [ %7, %set.body ]
  %5 = icmp ult i64 %set.i, %4
  br i1 %5, label %set.body, label %set.after

set.body:                                         ; preds = %set.cond
  %6 = getelementptr i8, ptr @map_value, i64 %set.i
  store i64 %2, ptr %6, align 1
  %7 = add i64 %set.i, 8
  br label %set.cond

set.after:                                        ; preds = %set.cond
  br label %set.cond2

set.cond2:                                        ; preds = %set.body3, %set.after
  %set.i4 = phi i64 [ %4, %set.after ], [ %10, %set.body3 ]
  %8 = icmp ult i64 %set.i4, %length
  br i1 %8, label %set.body3, label %set.after1

set.body3:                                        ; preds = %set.cond2
  %9 = getelementptr i8, ptr @map_value, i64 %set.i4
  store i8 %0, ptr %9, align 1
  %10 = add i64 %set.i4, 1
  br label %set.cond2

set.after1:                                       ; preds = %set.cond2
  ret ptr @map_value
}

define ptr @fill_virtual(ptr %destination, i32 %value, i64 %length) {
entry:
  %result = call ptr @memset(ptr %destination, i32 %value, i64 %length)
  ret ptr %result
}
