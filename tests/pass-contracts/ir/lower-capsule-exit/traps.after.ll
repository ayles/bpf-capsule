source_filename = "lower-capsule-exit-traps.ll"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpfel"

%fiber = type { i32, i32 }

@bpf_capsule_fibers = global [1 x %fiber] zeroinitializer

; Function Attrs: cold noreturn nounwind memory(inaccessiblemem: write)
declare void @llvm.trap() #0

; Function Attrs: nounwind
declare void @llvm.debugtrap() #1

define void @trap_leaf() !bpf.capsule !0 {
entry:
  %capsule.outcome.ptr = call ptr @__bpf_capsule_outcome_ptr()
  store i64 -60129542141, ptr %capsule.outcome.ptr, align 8, !bpf.capsule.outcome.store !0
  ret void
}

define void @trap_wrapper() !bpf.capsule !0 {
entry:
  call void @trap_leaf()
  ret void
}

define i32 @conditional_debugtrap(i1 %stop) !bpf.capsule !0 {
entry:
  br i1 %stop, label %trapped, label %continue

trapped:                                          ; preds = %entry
  %capsule.outcome.ptr = call ptr @__bpf_capsule_outcome_ptr()
  store i64 -60129542141, ptr %capsule.outcome.ptr, align 8, !bpf.capsule.outcome.store !0
  ret i32 0

continue:                                         ; preds = %entry
  br label %merge

merge:                                            ; preds = %continue
  ret i32 7
}

declare ptr @__bpf_capsule_outcome_ptr()

attributes #0 = { cold noreturn nounwind memory(inaccessiblemem: write) }
attributes #1 = { nounwind }

!0 = !{}
