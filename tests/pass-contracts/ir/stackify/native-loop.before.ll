source_filename = "stackify-native-loop.ll"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpfel"

%fiber_control = type { i32, i32, i64, i64, i64, i32, i32 }
%config = type { i32, i32, i32, i32, i32, i32, i32, i32, i32, i32, i32, i32, i64 }

@bpf_capsule_fibers = global [1 x %fiber_control] zeroinitializer, section ".bss.bpfctrl", align 8
@bpf_capsule_config = constant %config { i32 0, i32 4096, i32 0, i32 0, i32 1, i32 4096, i32 1, i32 0, i32 1, i32 0, i32 1112556353, i32 5, i64 0 }, section ".rodata.bpfconfig", align 4

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

define i32 @native_loop() !bpf.capsule !0 {
entry:
  br label %loop

loop:                                             ; preds = %loop, %entry
  %index = phi i32 [ 0, %entry ], [ %next, %loop ]
  %next = add i32 %index, 1
  %more = icmp ult i32 %next, 4
  br i1 %more, label %loop, label %exit

exit:                                             ; preds = %loop
  ret i32 %next
}

define i32 @start(i32 %fiber) section "syscall" !bpf.native !0 {
entry:
  %result = call i32 @native_loop() [ "bpf.capsule.call"(i32 %fiber) ]
  ret i32 %result
}

attributes #0 = { "capsule.trampoline" }

!0 = !{}
