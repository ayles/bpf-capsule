source_filename = "lower-capsule-exit.ll"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpfel"

%fiber = type { i32, i32 }

@bpf_capsule_fibers = global [1 x %fiber] zeroinitializer

declare void @__bpf_capsule_exit(i32)

; Function Attrs: noreturn
define void @exit_leaf(i32 %code) #0 !bpf.capsule !0 {
entry:
  call void @__bpf_capsule_exit(i32 %code)
  unreachable
}

; Function Attrs: noreturn
define void @panic_wrapper(i32 %code) #0 !bpf.capsule !0 {
entry:
  call void @exit_leaf(i32 %code)
  unreachable
}

define i32 @conditional_abort(i1 %stop, i32 %code) !bpf.capsule !0 {
entry:
  br i1 %stop, label %abort, label %continue

abort:                                            ; preds = %entry
  call void @panic_wrapper(i32 %code)
  unreachable

continue:                                         ; preds = %entry
  ret i32 7
}

attributes #0 = { noreturn }

!0 = !{}
