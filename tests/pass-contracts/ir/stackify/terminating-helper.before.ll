source_filename = "stackify-terminating-helper.ll"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpfel"

%fiber_control = type { i32, i32, i64, i64, i64, i32, i32 }
%config = type { i32, i32, i32, i32, i32, i32, i32, i32, i32, i32, i32, i32, i64 }

@bpf_capsule_fibers = global [1 x %fiber_control] zeroinitializer, section ".bss.bpfctrl", align 8
@bpf_capsule_config = constant %config { i32 0, i32 4096, i32 0, i32 0, i32 1, i32 4096, i32 1, i32 0, i32 1, i32 0, i32 1112556353, i32 8, i64 0 }, section ".rodata.bpfconfig", align 4

declare i32 @__bpf_capsule_trampoline_step(i32, ptr)

declare ptr @__bpf_capsule_outcome_ptr()

define i32 @__bpf_capsule_trampoline_l1(i32 %fiber, ptr %control) #0 {
entry:
  %status = call i32 @__bpf_capsule_trampoline_step(i32 %fiber, ptr %control)
  ret i32 %status
}

define i32 @__bpf_capsule_trampoline(i32 %fiber) #0 {
entry:
  %control = getelementptr [1 x %fiber_control], ptr @bpf_capsule_fibers, i32 0, i32 %fiber
  %status = call i32 @__bpf_capsule_trampoline_l1(i32 %fiber, ptr %control)
  ret i32 %status
}

define i32 @terminating_helper(i1 %fail) !bpf.capsule !0 {
entry:
  br i1 %fail, label %outcome.route, label %return

outcome.route:                                    ; preds = %entry
  br i1 %fail, label %outcome.one, label %outcome.two

outcome.one:                                      ; preds = %outcome.route
  %outcome = call ptr @__bpf_capsule_outcome_ptr()
  store i64 -4294967293, ptr %outcome, align 8, !bpf.capsule.outcome.store !0
  br label %outcome.return

outcome.two:                                      ; preds = %outcome.route
  %outcome.2 = call ptr @__bpf_capsule_outcome_ptr()
  store i64 -4294967292, ptr %outcome.2, align 8, !bpf.capsule.outcome.store !0
  br label %outcome.return

outcome.return:                                   ; preds = %outcome.two, %outcome.one
  ret i32 0

return:                                           ; preds = %entry
  ret i32 7
}

define i32 @mixed_terminating_helper(i1 %fail) !bpf.capsule !0 {
entry:
  br i1 %fail, label %outcome, label %ordinary

outcome:                                          ; preds = %entry
  %outcome.ptr = call ptr @__bpf_capsule_outcome_ptr()
  store i64 -4294967291, ptr %outcome.ptr, align 8, !bpf.capsule.outcome.store !0
  br label %return

ordinary:                                         ; preds = %entry
  br label %return

return:                                           ; preds = %ordinary, %outcome
  ret i32 11
}

define i32 @root(i1 %fail) !bpf.capsule !0 {
entry:
  %mixed = call i32 @mixed_terminating_helper(i1 %fail)
  %first = call i32 @terminating_helper(i1 %fail)
  %second = call i32 @terminating_helper(i1 false)
  %sum = add i32 %first, %second
  %total = add i32 %sum, %mixed
  ret i32 %total
}

define i32 @start(i32 %fiber) section "syscall" !bpf.native !0 {
entry:
  %result = call i32 @root(i1 false) [ "bpf.capsule.call"(i32 %fiber) ]
  ret i32 %result
}

attributes #0 = { "capsule.trampoline" }

!0 = !{}
