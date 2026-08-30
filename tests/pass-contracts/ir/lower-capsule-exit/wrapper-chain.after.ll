source_filename = "lower-capsule-exit.ll"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpfel"

%fiber = type { i32, i32 }

@bpf_capsule_fibers = global [1 x %fiber] zeroinitializer

define void @exit_leaf(i32 %code) !bpf.capsule !0 {
entry:
  %0 = sext i32 %code to i64
  %1 = shl i64 %0, 32
  %2 = or i64 %1, 3
  %capsule.outcome.ptr = call ptr @__bpf_capsule_outcome_ptr()
  store i64 %2, ptr %capsule.outcome.ptr, align 8, !bpf.capsule.outcome.store !0
  ret void
}

define void @panic_wrapper(i32 %code) !bpf.capsule !0 {
entry:
  call void @exit_leaf(i32 %code)
  ret void
}

define i32 @conditional_abort(i1 %stop, i32 %code) !bpf.capsule !0 {
entry:
  br i1 %stop, label %abort, label %continue

abort:                                            ; preds = %entry
  call void @panic_wrapper(i32 %code)
  ret i32 0

continue:                                         ; preds = %entry
  ret i32 7
}

declare ptr @__bpf_capsule_outcome_ptr()

!0 = !{}
