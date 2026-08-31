source_filename = "lower-capsule-call.ll"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpfel"

%fiber = type { i32, i32, i64, i64, i64, i32, i32 }

@bpf_capsule_fibers = global [4 x %fiber] zeroinitializer

define i64 @scalar_root(ptr %ordinary, i32 %value) {
entry:
  %ordinary.bits = ptrtoint ptr %ordinary to i64
  %value.wide = zext i32 %value to i64
  %result = add i64 %ordinary.bits, %value.wide
  ret i64 %result
}

define void @void_root() {
entry:
  ret void
}

define i32 @call_scalar(ptr %context, ptr %ordinary, i32 %fiber.index, i16 %value) section "xdp" {
entry:
  %output = alloca i64, align 8
  %0 = zext i16 %value to i32
  %1 = call i64 @scalar_root(ptr %ordinary, i32 %0) [ "bpf.capsule.call"(i32 %fiber.index, ptr %context) ]
  %capsule.control = getelementptr inbounds [4 x %fiber], ptr @bpf_capsule_fibers, i32 0, i32 %fiber.index
  %2 = getelementptr inbounds nuw %fiber, ptr %capsule.control, i32 0, i32 0
  %3 = getelementptr inbounds nuw %fiber, ptr %capsule.control, i32 0, i32 5
  %4 = load i32, ptr %2, align 4
  %5 = icmp eq i32 %4, 3
  %6 = icmp eq i32 %4, 2
  %7 = load i32, ptr %3, align 4
  %8 = icmp ne i32 %7, 0
  %9 = select i1 %8, i32 1, i32 0
  %10 = select i1 %6, i32 2, i32 %9
  %11 = select i1 %5, i32 3, i32 %10
  %12 = icmp eq i32 %11, 0
  br i1 %12, label %13, label %14

13:                                               ; preds = %entry
  store i64 %1, ptr %output, align 8
  br label %14

14:                                               ; preds = %13, %entry
  ret i32 %11
}

define i32 @call_void(i32 %fiber.index) section "xdp" {
entry:
  call void @void_root() [ "bpf.capsule.call"(i32 %fiber.index) ]
  %capsule.control = getelementptr inbounds [4 x %fiber], ptr @bpf_capsule_fibers, i32 0, i32 %fiber.index
  %0 = getelementptr inbounds nuw %fiber, ptr %capsule.control, i32 0, i32 0
  %1 = getelementptr inbounds nuw %fiber, ptr %capsule.control, i32 0, i32 5
  %2 = load i32, ptr %0, align 4
  %3 = icmp eq i32 %2, 3
  %4 = icmp eq i32 %2, 2
  %5 = load i32, ptr %1, align 4
  %6 = icmp ne i32 %5, 0
  %7 = select i1 %6, i32 1, i32 0
  %8 = select i1 %4, i32 2, i32 %7
  %9 = select i1 %3, i32 3, i32 %8
  ret i32 %9
}
