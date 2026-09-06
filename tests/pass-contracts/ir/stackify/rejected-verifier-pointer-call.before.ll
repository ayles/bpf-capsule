source_filename = "stackify-rejected-verifier-pointer-call.ll"
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

define void @recursive_callee(i64 %value) !bpf.capsule !0 {
entry:
  %again = icmp sgt i64 %value, 0
  br i1 %again, label %recurse, label %done

recurse:                                          ; preds = %entry
  %next = add i64 %value, -1
  call void @recursive_callee(i64 %next)
  br label %done

done:                                             ; preds = %recurse, %entry
  ret void
}

define i64 @pointer_across_call() !bpf.capsule !0 {
entry:
  %map.value = call ptr inttoptr (i64 1 to ptr)()
  %before = load i64, ptr %map.value, align 8
  call void @recursive_callee(i64 %before)
  %after = load i64, ptr %map.value, align 8
  ret i64 %after
}

define i32 @start(i32 %fiber) section "syscall" !bpf.native !0 {
entry:
  %result = call i64 @pointer_across_call() [ "bpf.capsule.call"(i32 %fiber) ]
  %truncated = trunc i64 %result to i32
  ret i32 %truncated
}

attributes #0 = { "capsule.trampoline" }

!0 = !{}
