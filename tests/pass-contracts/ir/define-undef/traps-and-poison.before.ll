source_filename = "define-undef.ll"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpfel"

%fiber = type { i32, i32 }

@bpf_capsule_fibers = global [1 x %fiber] zeroinitializer

; Function Attrs: cold noreturn nounwind memory(inaccessiblemem: write)
declare void @llvm.trap() #0

; Function Attrs: nounwind
declare void @llvm.debugtrap() #1

define i32 @poison_values(i1 %condition) !bpf.capsule !0 {
entry:
  %selected = select i1 %condition, i32 poison, i32 undef
  ret i32 %selected
}

define { i32, ptr } @aggregate_poison() !bpf.capsule !0 {
entry:
  ret { i32, ptr } poison
}

define i32 @trap_path() !bpf.capsule !0 {
entry:
  call void @llvm.trap()
  unreachable
}

define i32 @debugtrap_path() !bpf.capsule !0 {
entry:
  call void @llvm.debugtrap()
  ret i32 7
}

define i32 @trap_with_successor(i1 %condition) !bpf.capsule !0 {
entry:
  br i1 %condition, label %trapped, label %normal

trapped:                                          ; preds = %entry
  call void @llvm.trap()
  br label %merge

normal:                                           ; preds = %entry
  br label %merge

merge:                                            ; preds = %normal, %trapped
  %value = phi i32 [ 1, %trapped ], [ 2, %normal ]
  ret i32 %value
}

define void @unreachable_path() !bpf.capsule !0 {
entry:
  unreachable
}

attributes #0 = { cold noreturn nounwind memory(inaccessiblemem: write) }
attributes #1 = { nounwind }

!0 = !{}
