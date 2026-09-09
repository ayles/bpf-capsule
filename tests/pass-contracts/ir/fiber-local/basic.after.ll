source_filename = "fiber-local.ll"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpfel"

%struct.__bpf_capsule_fiber_control = type { i32, i32, i64, i64 }
%capsule.fiber_local = type { i64, i32, [2 x i16], i8 }

@bpf_capsule_fibers = global [4 x %struct.__bpf_capsule_fiber_control] zeroinitializer, section ".data.capsule.fibers", align 8
@.str = private unnamed_addr constant [20 x i8] c"capsule.fiber_local\00", section "llvm.metadata"
@.str.1 = private unnamed_addr constant [14 x i8] c"fiber-local.c\00", section "llvm.metadata"
@.str.2 = private unnamed_addr constant [14 x i8] c"capsule.entry\00", section "llvm.metadata"
@llvm.global.annotations = appending global [1 x { ptr, ptr, ptr, i32, ptr }] [{ ptr, ptr, ptr, i32, ptr } { ptr @entry, ptr @.str.2, ptr @.str.1, i32 9, ptr null }], section "llvm.metadata"
@__bpf_capsule_fiber_locals = internal global [4 x %capsule.fiber_local] [%capsule.fiber_local { i64 0, i32 256, [2 x i16] [i16 1, i16 2], i8 7 }, %capsule.fiber_local { i64 0, i32 256, [2 x i16] [i16 1, i16 2], i8 7 }, %capsule.fiber_local { i64 0, i32 256, [2 x i16] [i16 1, i16 2], i8 7 }, %capsule.fiber_local { i64 0, i32 256, [2 x i16] [i16 1, i16 2], i8 7 }], align 8, !bpf.capsule.owned !0
@__bpf_capsule_fiber_local_image = internal constant %capsule.fiber_local { i64 0, i32 256, [2 x i16] [i16 1, i16 2], i8 7 }, align 8

define i32 @bump(i32 %delta) {
entry:
  %fiber = call i32 @__bpf_capsule_current_fiber_index()
  %fiber.locals = getelementptr inbounds [4 x %capsule.fiber_local], ptr @__bpf_capsule_fiber_locals, i64 0, i32 %fiber
  %table = getelementptr inbounds nuw %capsule.fiber_local, ptr %fiber.locals, i32 0, i32 2
  %counter = getelementptr inbounds nuw %capsule.fiber_local, ptr %fiber.locals, i32 0, i32 1
  %value = load i32, ptr %counter, align 4
  %next = add i32 %value, %delta
  store i32 %next, ptr %counter, align 4
  %0 = getelementptr inbounds [2 x i16], ptr %table, i64 0, i64 1
  %second = load i16, ptr %0, align 2
  %widened = zext i16 %second to i32
  %sum = add i32 %next, %widened
  ret i32 %sum
}

define i64 @accumulate(i64 %delta, i1 %flag) {
entry:
  %fiber = call i32 @__bpf_capsule_current_fiber_index()
  %fiber.locals = getelementptr inbounds [4 x %capsule.fiber_local], ptr @__bpf_capsule_fiber_locals, i64 0, i32 %fiber
  %rust_local = getelementptr inbounds nuw %capsule.fiber_local, ptr %fiber.locals, i32 0, i32 3
  %wide = getelementptr inbounds nuw %capsule.fiber_local, ptr %fiber.locals, i32 0, i32 0
  br i1 %flag, label %then, label %join

then:                                             ; preds = %entry
  store i8 0, ptr %rust_local, align 1
  br label %join

join:                                             ; preds = %then, %entry
  %slot = phi ptr [ %wide, %then ], [ %wide, %entry ]
  %value = load i64, ptr %slot, align 8
  %next = add i64 %value, %delta
  store i64 %next, ptr %slot, align 8
  ret i64 %next
}

define i32 @entry() {
entry:
  ret i32 0
}

define void @__bpf_capsule_fiber_local_reset(i32 %fiber) {
entry:
  %fiber.locals = getelementptr inbounds [4 x %capsule.fiber_local], ptr @__bpf_capsule_fiber_locals, i64 0, i32 %fiber
  br label %reset.words

reset.words:                                      ; preds = %reset.words, %entry
  %reset.words.index = phi i64 [ 0, %entry ], [ %3, %reset.words ]
  %0 = getelementptr i8, ptr @__bpf_capsule_fiber_local_image, i64 %reset.words.index
  %1 = load i64, ptr %0, align 8
  %2 = getelementptr i8, ptr %fiber.locals, i64 %reset.words.index
  store i64 %1, ptr %2, align 8
  %3 = add i64 %reset.words.index, 8
  %4 = icmp ult i64 %3, 24
  br i1 %4, label %reset.words, label %reset.words.done

reset.words.done:                                 ; preds = %reset.words
  ret void
}

declare i32 @__bpf_capsule_current_fiber_index()

!0 = !{}
