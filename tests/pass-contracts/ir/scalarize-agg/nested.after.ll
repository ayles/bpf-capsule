source_filename = "scalarize-agg.ll"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpfel"

%nested = type { i32, [2 x i16] }

define %nested @copy(ptr %source, ptr %destination) {
entry:
  %0 = getelementptr inbounds %nested, ptr %source, i32 0, i32 0
  %1 = load volatile i32, ptr %0, align 4
  %2 = insertvalue %nested poison, i32 %1, 0
  %3 = getelementptr inbounds %nested, ptr %source, i32 0, i32 1
  %4 = getelementptr inbounds [2 x i16], ptr %3, i32 0, i32 0
  %5 = load volatile i16, ptr %4, align 4
  %6 = insertvalue [2 x i16] poison, i16 %5, 0
  %7 = getelementptr inbounds [2 x i16], ptr %3, i32 0, i32 1
  %8 = load volatile i16, ptr %7, align 2
  %9 = insertvalue [2 x i16] %6, i16 %8, 1
  %10 = insertvalue %nested %2, [2 x i16] %9, 1
  %11 = getelementptr inbounds %nested, ptr %destination, i32 0, i32 0
  %12 = extractvalue %nested %10, 0
  store volatile i32 %12, ptr %11, align 4
  %13 = getelementptr inbounds %nested, ptr %destination, i32 0, i32 1
  %14 = extractvalue %nested %10, 1
  %15 = getelementptr inbounds [2 x i16], ptr %13, i32 0, i32 0
  %16 = extractvalue [2 x i16] %14, 0
  store volatile i16 %16, ptr %15, align 4
  %17 = getelementptr inbounds [2 x i16], ptr %13, i32 0, i32 1
  %18 = extractvalue [2 x i16] %14, 1
  store volatile i16 %18, ptr %17, align 2
  ret %nested %10
}

define i128 @copy_i128(ptr %source, ptr %destination) {
entry:
  %0 = getelementptr i8, ptr %source, i64 0
  %1 = load volatile i64, ptr %0, align 16
  %2 = getelementptr i8, ptr %source, i64 8
  %3 = load volatile i64, ptr %2, align 8
  %4 = zext i64 %1 to i128
  %5 = zext i64 %3 to i128
  %6 = shl i128 %5, 64
  %7 = or i128 %4, %6
  %8 = trunc i128 %7 to i64
  %9 = lshr i128 %7, 64
  %10 = trunc i128 %9 to i64
  %11 = getelementptr i8, ptr %destination, i64 0
  store volatile i64 %8, ptr %11, align 16
  %12 = getelementptr i8, ptr %destination, i64 8
  store volatile i64 %10, ptr %12, align 8
  ret i128 %7
}
