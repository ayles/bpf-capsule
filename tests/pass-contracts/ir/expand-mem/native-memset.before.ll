source_filename = "expand-native-memset.ll"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpfel"

@map_value = global [64 x i8] zeroinitializer, section ".data.map"

declare ptr @memset(ptr, i32, i64)

define ptr @fill_map(i32 %value, i64 %length) {
entry:
  %result = call ptr @memset(ptr @map_value, i32 %value, i64 %length)
  ret ptr %result
}

define ptr @fill_virtual(ptr %destination, i32 %value, i64 %length) {
entry:
  %result = call ptr @memset(ptr %destination, i32 %value, i64 %length)
  ret ptr %result
}
