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
  %selected = select i1 %condition, i32 0, i32 0
  ret i32 %selected
}

define { i32, ptr } @aggregate_poison() !bpf.capsule !0 {
entry:
  ret { i32, ptr } zeroinitializer
}

define i32 @trap_path() !bpf.capsule !0 {
entry:
  %capsule.outcome.ptr = call ptr @__bpf_capsule_outcome_ptr()
  store i64 -60129542141, ptr %capsule.outcome.ptr, align 8, !bpf.capsule.outcome.store !0
  ret i32 0
}

define i32 @debugtrap_path() !bpf.capsule !0 {
entry:
  %capsule.outcome.ptr = call ptr @__bpf_capsule_outcome_ptr()
  store i64 -60129542141, ptr %capsule.outcome.ptr, align 8, !bpf.capsule.outcome.store !0
  ret i32 0
}

define i32 @trap_with_successor(i1 %condition) !bpf.capsule !0 {
entry:
  br i1 %condition, label %trapped, label %normal

trapped:                                          ; preds = %entry
  %capsule.outcome.ptr = call ptr @__bpf_capsule_outcome_ptr()
  store i64 -60129542141, ptr %capsule.outcome.ptr, align 8, !bpf.capsule.outcome.store !0
  ret i32 0

normal:                                           ; preds = %entry
  br label %merge

merge:                                            ; preds = %normal
  ret i32 2
}

define void @unreachable_path() !bpf.capsule !0 {
entry:
  %capsule.outcome.ptr = call ptr @__bpf_capsule_outcome_ptr()
  store i64 -55834574845, ptr %capsule.outcome.ptr, align 8, !bpf.capsule.outcome.store !0
  ret void
}

declare ptr @__bpf_capsule_outcome_ptr()

attributes #0 = { cold noreturn nounwind memory(inaccessiblemem: write) }
attributes #1 = { nounwind }

!0 = !{}
