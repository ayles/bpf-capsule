source_filename = "expand-native-memcpy.ll"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpfel"

@map_value = global [64 x i8] zeroinitializer, section ".data.map"

declare ptr @memcpy(ptr, ptr, i64)

define ptr @copy_to_map(ptr %source, i64 %length) {
entry:
  %result = call ptr @memcpy(ptr @map_value, ptr %source, i64 %length)
  ret ptr %result
}

define ptr @copy_virtual(ptr %destination, ptr %source, i64 %length) {
entry:
  %result = call ptr @memcpy(ptr %destination, ptr %source, i64 %length)
  ret ptr %result
}
