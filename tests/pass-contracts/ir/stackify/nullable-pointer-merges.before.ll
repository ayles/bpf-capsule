source_filename = "stackify-nullable-pointer-merges.ll"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpfel"

%fiber_control = type { i32, i32, i64, i64, i64, i32, i32 }
%config = type { i32, i32, i32, i32, i32, i32, i32, i32, i32, i32, i32, i32, i64 }

@bpf_capsule_fibers = global [1 x %fiber_control] zeroinitializer, section ".bss.bpfctrl", align 8
@bpf_capsule_config = constant %config { i32 0, i32 4096, i32 0, i32 0, i32 1, i32 4096, i32 1, i32 0, i32 1, i32 0, i32 1112556353, i32 8, i64 0 }, section ".rodata.bpfconfig", align 4

declare i32 @__bpf_capsule_trampoline_step(i32, ptr)

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

define i64 @root(i1 %choose) !bpf.capsule !0 {
entry:
  %selected = select i1 %choose, ptr null, ptr null
  br i1 %choose, label %left, label %right

left:                                             ; preds = %entry
  br label %merge

right:                                            ; preds = %entry
  br label %merge

merge:                                            ; preds = %right, %left
  %pointer = phi ptr [ %selected, %left ], [ null, %right ]
  %result = ptrtoint ptr %pointer to i64
  ret i64 %result
}

define i32 @start(i32 %fiber, i1 %choose) section "syscall" !bpf.native !0 {
entry:
  %result = call i64 @root(i1 %choose) [ "bpf.capsule.call"(i32 %fiber) ]
  %truncated = trunc i64 %result to i32
  ret i32 %truncated
}

attributes #0 = { "capsule.trampoline" }

!0 = !{}
