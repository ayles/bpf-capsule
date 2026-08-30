source_filename = "lower-capsule-call-sret.ll"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpfel"

%fiber = type { i32, i32, i64, i64, i64, i32, i32 }
%result = type { i64, i32 }

@bpf_capsule_fibers = global [1 x %fiber] zeroinitializer

define void @aggregate_root(ptr sret(%result) align 8 %output, i32 %value) {
entry:
  %wide = zext i32 %value to i64
  %first = insertvalue %result poison, i64 %wide, 0
  %complete = insertvalue %result %first, i32 %value, 1
  store %result %complete, ptr %output, align 8
  ret void
}

define i32 @call_aggregate(i32 %value) section "xdp" {
entry:
  %output = alloca %result, align 8
  %0 = call %result @aggregate_root.capsule.result(i32 %value) [ "bpf.capsule.call"(i32 0) ]
  %1 = load i32, ptr @bpf_capsule_fibers, align 4
  %2 = icmp eq i32 %1, 3
  %3 = icmp eq i32 %1, 2
  %4 = load i32, ptr getelementptr inbounds nuw (%fiber, ptr @bpf_capsule_fibers, i32 0, i32 5), align 4
  %5 = icmp ne i32 %4, 0
  %6 = select i1 %5, i32 1, i32 0
  %7 = select i1 %3, i32 2, i32 %6
  %8 = select i1 %2, i32 3, i32 %7
  %9 = icmp eq i32 %8, 0
  br i1 %9, label %10, label %11

10:                                               ; preds = %entry
  store %result %0, ptr %output, align 8
  br label %11

11:                                               ; preds = %10, %entry
  ret i32 %8
}

define internal %result @aggregate_root.capsule.result(i32 %0) {
entry:
  %result = alloca %result, align 8
  call void @aggregate_root(ptr sret(%result) align 8 %result, i32 %0)
  %1 = load %result, ptr %result, align 8
  ret %result %1
}
