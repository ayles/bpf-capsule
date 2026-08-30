source_filename = "expand-sret.ll"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpfel"

%pair = type { i64, i32 }

define internal void @make_pair(ptr noalias sret(%pair) align 8 %out, i64 %wide, i32 %narrow) {
entry:
  %wide.pointer = getelementptr inbounds %pair, ptr %out, i32 0, i32 0
  store i64 %wide, ptr %wide.pointer, align 8
  %narrow.pointer = getelementptr inbounds %pair, ptr %out, i32 0, i32 1
  store i32 %narrow, ptr %narrow.pointer, align 4
  ret void
}

define %pair @caller(i64 %wide, i32 %narrow) {
entry:
  %result = alloca %pair, align 8
  call void @make_pair(ptr sret(%pair) align 8 %result, i64 %wide, i32 %narrow)
  %value = load %pair, ptr %result, align 8
  ret %pair %value
}
