source_filename = "inline-policy-o2.ll"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpfel"

; Function Attrs: mustprogress nofree noinline norecurse nosync nounwind willreturn memory(none)
define internal fastcc i32 @blocked(i32 %value) unnamed_addr #0 {
entry:
  %result = add i32 %value, -7
  ret i32 %result
}

; Function Attrs: mustprogress nofree norecurse nosync nounwind willreturn memory(none)
define i32 @caller(i32 %value) local_unnamed_addr #1 {
entry:
  %0 = mul i32 %value, 5
  %result.i = add i32 %0, 15
  %c = tail call fastcc i32 @blocked(i32 %result.i)
  ret i32 %c
}

attributes #0 = { mustprogress nofree noinline norecurse nosync nounwind willreturn memory(none) }
attributes #1 = { mustprogress nofree norecurse nosync nounwind willreturn memory(none) }

!llvm.module.flags = !{!0}

!0 = !{i32 1, !"bpf.capsule.classes", i32 1}
