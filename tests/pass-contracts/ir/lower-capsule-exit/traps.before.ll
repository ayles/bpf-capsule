source_filename = "lower-capsule-exit-traps.ll"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpfel"

%fiber = type { i32, i32 }

@bpf_capsule_fibers = global [1 x %fiber] zeroinitializer

; Function Attrs: cold noreturn nounwind memory(inaccessiblemem: write)
declare void @llvm.trap() #0

; Function Attrs: nounwind
declare void @llvm.debugtrap() #1

; Function Attrs: noreturn
define void @trap_leaf() #2 !bpf.capsule !0 {
entry:
  call void @llvm.trap()
  unreachable
}

; Function Attrs: noreturn
define void @trap_wrapper() #2 !bpf.capsule !0 {
entry:
  call void @trap_leaf()
  unreachable
}

define i32 @conditional_debugtrap(i1 %stop) !bpf.capsule !0 {
entry:
  br i1 %stop, label %trapped, label %continue

trapped:                                          ; preds = %entry
  call void @llvm.debugtrap()
  br label %merge

continue:                                         ; preds = %entry
  br label %merge

merge:                                            ; preds = %continue, %trapped
  %result = phi i32 [ 0, %trapped ], [ 7, %continue ]
  ret i32 %result
}

attributes #0 = { cold noreturn nounwind memory(inaccessiblemem: write) }
attributes #1 = { nounwind }
attributes #2 = { noreturn }

!0 = !{}
