source_filename = "stackify-rejected-verifier-pointer-loop.ll"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpfel"

%fiber_control = type { i32, i32, i64, i64, i64, i32, i32 }
%config = type { i32, i32, i32, i32, i32, i32, i32, i32, i32, i32, i32, i32, i64 }

@bpf_capsule_fibers = global [1 x %fiber_control] zeroinitializer, section ".bss.bpfctrl", align 8
@bpf_capsule_config = constant %config zeroinitializer, section ".rodata.bpfconfig", align 4

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

define i64 @pointer_across_loop(i64 %count) !bpf.capsule !0 {
entry:
  %map.value = call ptr inttoptr (i64 1 to ptr)()
  br label %loop

loop:                                             ; preds = %loop, %entry
  %index = phi i64 [ 0, %entry ], [ %next, %loop ]
  %sum = phi i64 [ 0, %entry ], [ %updated, %loop ]
  call void asm sideeffect "r0 = r0", ""()
  %current = load i64, ptr %map.value, align 8
  %updated = add i64 %sum, %current
  %next = add i64 %index, 1
  %more = icmp ult i64 %next, %count
  br i1 %more, label %loop, label %exit

exit:                                             ; preds = %loop
  ret i64 %updated
}

define i32 @start(i32 %fiber) section "syscall" !bpf.native !0 {
entry:
  %result = call i64 @pointer_across_loop(i64 64) [ "bpf.capsule.call"(i32 %fiber) ]
  %truncated = trunc i64 %result to i32
  ret i32 %truncated
}

attributes #0 = { "capsule.trampoline" }

!0 = !{}
