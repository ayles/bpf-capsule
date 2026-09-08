source_filename = "fiber-local.ll"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpfel"

%struct.__bpf_capsule_fiber_control = type { i32, i32, i64, i64 }

@bpf_capsule_fibers = global [4 x %struct.__bpf_capsule_fiber_control] zeroinitializer, section ".data.capsule.fibers", align 8
@counter = global i32 256, align 4
@wide = internal global i64 0, align 8
@table = global [2 x i16] [i16 1, i16 2], align 2
@rust_local = thread_local global i8 7, align 1
@.str = private unnamed_addr constant [20 x i8] c"capsule.fiber_local\00", section "llvm.metadata"
@.str.1 = private unnamed_addr constant [14 x i8] c"fiber-local.c\00", section "llvm.metadata"
@.str.2 = private unnamed_addr constant [14 x i8] c"capsule.entry\00", section "llvm.metadata"
@llvm.global.annotations = appending global [4 x { ptr, ptr, ptr, i32, ptr }] [{ ptr, ptr, ptr, i32, ptr } { ptr @counter, ptr @.str, ptr @.str.1, i32 5, ptr null }, { ptr, ptr, ptr, i32, ptr } { ptr @wide, ptr @.str, ptr @.str.1, i32 6, ptr null }, { ptr, ptr, ptr, i32, ptr } { ptr @table, ptr @.str, ptr @.str.1, i32 7, ptr null }, { ptr, ptr, ptr, i32, ptr } { ptr @entry, ptr @.str.2, ptr @.str.1, i32 9, ptr null }], section "llvm.metadata"

define i32 @bump(i32 %delta) {
entry:
  %value = load i32, ptr @counter, align 4
  %next = add i32 %value, %delta
  store i32 %next, ptr @counter, align 4
  %second = load i16, ptr getelementptr inbounds ([2 x i16], ptr @table, i64 0, i64 1), align 2
  %widened = zext i16 %second to i32
  %sum = add i32 %next, %widened
  ret i32 %sum
}

define i64 @accumulate(i64 %delta, i1 %flag) {
entry:
  br i1 %flag, label %then, label %join

then:                                             ; preds = %entry
  store i8 0, ptr @rust_local, align 1
  br label %join

join:                                             ; preds = %then, %entry
  %slot = phi ptr [ @wide, %then ], [ @wide, %entry ]
  %value = load i64, ptr %slot, align 8
  %next = add i64 %value, %delta
  store i64 %next, ptr %slot, align 8
  ret i64 %next
}

define i32 @entry() {
entry:
  ret i32 0
}

define weak void @__bpf_capsule_fiber_local_reset(i32 %fiber) {
entry:
  ret void
}
