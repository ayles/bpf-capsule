source_filename = "lower-managed-atomics.ll"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpfel"

@byte = global i8 0, align 4
@half = global i16 0, align 4
@word = global i32 0, align 4
@wide = global i64 0, align 8
@pointer = global ptr null, align 8

define i64 @managed(i8 %byte.value, i16 %half.value, i32 %word.value, i64 %wide.value, ptr %pointer.value) !bpf.capsule !0 {
entry:
  %byte.old = atomicrmw add ptr @byte, i8 %byte.value seq_cst, align 1
  %half.cas = cmpxchg ptr @half, i16 7, i16 %half.value seq_cst seq_cst, align 2
  %word.old = atomicrmw or ptr @word, i32 %word.value seq_cst, align 4
  %wide.load = load atomic i64, ptr @wide acquire, align 8
  store atomic i64 %wide.value, ptr @wide release, align 8
  %pointer.load = load atomic ptr, ptr @pointer seq_cst, align 8
  store atomic ptr %pointer.value, ptr @pointer seq_cst, align 8
  fence syncscope("singlethread") acq_rel
  fence seq_cst
  %byte.wide = zext i8 %byte.old to i64
  %word.wide = zext i32 %word.old to i64
  %sum = add i64 %wide.load, %byte.wide
  %result = add i64 %sum, %word.wide
  ret i64 %result
}

!0 = !{}
