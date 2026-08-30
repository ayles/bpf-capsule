source_filename = "expand-native-memcpy.ll"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpfel"

@map_value = global [64 x i8] zeroinitializer, section ".data.map"

declare ptr @memcpy(ptr, ptr, i64)

define ptr @copy_to_map(ptr %source, i64 %length) {
entry:
  %0 = udiv i64 %length, 8
  %1 = mul i64 %0, 8
  br label %copy.cond

copy.cond:                                        ; preds = %copy.body, %entry
  %copy.i = phi i64 [ 0, %entry ], [ %6, %copy.body ]
  %2 = icmp ult i64 %copy.i, %1
  br i1 %2, label %copy.body, label %copy.after

copy.body:                                        ; preds = %copy.cond
  %3 = getelementptr i8, ptr %source, i64 %copy.i
  %4 = load i64, ptr %3, align 1
  %5 = getelementptr i8, ptr @map_value, i64 %copy.i
  store i64 %4, ptr %5, align 1
  %6 = add i64 %copy.i, 8
  br label %copy.cond

copy.after:                                       ; preds = %copy.cond
  br label %copy.cond2

copy.cond2:                                       ; preds = %copy.body3, %copy.after
  %copy.i4 = phi i64 [ %1, %copy.after ], [ %11, %copy.body3 ]
  %7 = icmp ult i64 %copy.i4, %length
  br i1 %7, label %copy.body3, label %copy.after1

copy.body3:                                       ; preds = %copy.cond2
  %8 = getelementptr i8, ptr %source, i64 %copy.i4
  %9 = load i8, ptr %8, align 1
  %10 = getelementptr i8, ptr @map_value, i64 %copy.i4
  store i8 %9, ptr %10, align 1
  %11 = add i64 %copy.i4, 1
  br label %copy.cond2

copy.after1:                                      ; preds = %copy.cond2
  ret ptr @map_value
}

define ptr @copy_virtual(ptr %destination, ptr %source, i64 %length) {
entry:
  %result = call ptr @memcpy(ptr %destination, ptr %source, i64 %length)
  ret ptr %result
}
