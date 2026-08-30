source_filename = "expand-sret.ll"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpfel"

%pair = type { i64, i32 }

define %pair @caller(i64 %wide, i32 %narrow) {
entry:
  %result = alloca %pair, align 8
  %0 = call %pair @make_pair(i64 %wide, i32 %narrow)
  store %pair %0, ptr %result, align 8
  %value = load %pair, ptr %result, align 8
  ret %pair %value
}

define internal %pair @make_pair(i64 %wide, i32 %narrow) {
entry:
  %0 = alloca %pair, align 8
  %wide.pointer = getelementptr inbounds %pair, ptr %0, i32 0, i32 0
  store i64 %wide, ptr %wide.pointer, align 8
  %narrow.pointer = getelementptr inbounds %pair, ptr %0, i32 0, i32 1
  store i32 %narrow, ptr %narrow.pointer, align 4
  %1 = load %pair, ptr %0, align 8
  ret %pair %1
}
