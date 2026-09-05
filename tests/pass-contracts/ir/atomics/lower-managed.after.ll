source_filename = "lower-managed-atomics.ll"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpfel"

@byte = global i8 0, align 4
@half = global i16 0, align 4
@word = global i32 0, align 4
@wide = global i64 0, align 8
@pointer = global ptr null, align 8
@__bpf_capsule_atomic_fence = internal global i32 0, section ".data.bpfatomic", align 4

define i64 @managed(i8 %byte.value, i16 %half.value, i32 %word.value, i64 %wide.value, ptr %pointer.value) !bpf.capsule !0 {
entry:
  %0 = and i64 ptrtoint (ptr @byte to i64), -4
  %1 = inttoptr i64 %0 to ptr
  %2 = load atomic i32, ptr %1 monotonic, align 4
  br label %atomic.retry

atomic.retry:                                     ; preds = %atomic.retry, %entry
  %atomic.current = phi i32 [ %2, %entry ], [ %12, %atomic.retry ]
  %3 = lshr i32 %atomic.current, 0
  %4 = trunc i32 %3 to i8
  %5 = add i8 %4, %byte.value
  %6 = zext i8 %5 to i32
  %7 = shl i32 %6, 0
  %8 = and i32 %atomic.current, -256
  %9 = and i32 %7, 255
  %10 = or i32 %8, %9
  %11 = cmpxchg ptr %1, i32 %atomic.current, i32 %10 seq_cst seq_cst, align 4
  %12 = extractvalue { i32, i1 } %11, 0
  %13 = extractvalue { i32, i1 } %11, 1
  br i1 %13, label %atomic.done, label %atomic.retry

atomic.done:                                      ; preds = %atomic.retry
  %14 = and i64 ptrtoint (ptr @half to i64), -4
  %15 = inttoptr i64 %14 to ptr
  %16 = load atomic i32, ptr %15 monotonic, align 4
  br label %atomic.retry2

atomic.retry2:                                    ; preds = %atomic.attempt, %atomic.done
  %atomic.current3 = phi i32 [ %16, %atomic.done ], [ %26, %atomic.attempt ]
  %17 = lshr i32 %atomic.current3, 0
  %18 = trunc i32 %17 to i16
  %19 = icmp eq i16 %18, 7
  br i1 %19, label %atomic.attempt, label %atomic.done1

atomic.attempt:                                   ; preds = %atomic.retry2
  %20 = zext i16 %half.value to i32
  %21 = shl i32 %20, 0
  %22 = and i32 %atomic.current3, -65536
  %23 = and i32 %21, 65535
  %24 = or i32 %22, %23
  %25 = cmpxchg ptr %15, i32 %atomic.current3, i32 %24 seq_cst seq_cst, align 4
  %26 = extractvalue { i32, i1 } %25, 0
  %27 = extractvalue { i32, i1 } %25, 1
  br i1 %27, label %atomic.done1, label %atomic.retry2

atomic.done1:                                     ; preds = %atomic.attempt, %atomic.retry2
  %atomic.exchanged = phi i1 [ false, %atomic.retry2 ], [ true, %atomic.attempt ]
  %28 = insertvalue { i16, i1 } poison, i16 %18, 0
  %29 = insertvalue { i16, i1 } %28, i1 %atomic.exchanged, 1
  %30 = load atomic i32, ptr @word monotonic, align 4
  br label %atomic.retry5

atomic.retry5:                                    ; preds = %atomic.retry5, %atomic.done1
  %atomic.current6 = phi i32 [ %30, %atomic.done1 ], [ %33, %atomic.retry5 ]
  %31 = or i32 %atomic.current6, %word.value
  %32 = cmpxchg ptr @word, i32 %atomic.current6, i32 %31 seq_cst seq_cst, align 4
  %33 = extractvalue { i32, i1 } %32, 0
  %34 = extractvalue { i32, i1 } %32, 1
  br i1 %34, label %atomic.done4, label %atomic.retry5

atomic.done4:                                     ; preds = %atomic.retry5
  %35 = atomicrmw add ptr @wide, i64 0 seq_cst, align 8
  %36 = atomicrmw xchg ptr @wide, i64 %wide.value seq_cst, align 8
  %37 = atomicrmw add ptr @pointer, i64 0 seq_cst, align 8
  %38 = inttoptr i64 %37 to ptr
  %39 = ptrtoint ptr %pointer.value to i64
  %40 = atomicrmw xchg ptr @pointer, i64 %39 seq_cst, align 8
  fence syncscope("singlethread") acq_rel
  %41 = atomicrmw xchg ptr @__bpf_capsule_atomic_fence, i32 0 seq_cst, align 4
  %byte.wide = zext i8 %4 to i64
  %word.wide = zext i32 %atomic.current6 to i64
  %sum = add i64 %35, %byte.wide
  %result = add i64 %sum, %word.wide
  ret i64 %result
}

!0 = !{}
