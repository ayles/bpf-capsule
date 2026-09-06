source_filename = "stackify-rejected-sectioned-pointer-call.ll"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpfel"

%fiber_control = type { i32, i32, i64, i64, i64, i32, i32 }
%config = type { i32, i32, i32, i32, i32, i32, i32, i32, i32, i32, i32, i32, i64 }
%control = type { i64, i64 }

@bpf_capsule_fibers = global [1 x %fiber_control] zeroinitializer, section ".bss.bpfctrl", align 8
@bpf_capsule_config = constant %config zeroinitializer, section ".rodata.bpfconfig", align 4
@sectioned_control = global %control zeroinitializer, section ".data.control", align 8

declare i32 @__bpf_capsule_trampoline_step(i32, ptr)

define i32 @__bpf_capsule_trampoline_l1(i32 %fiber, ptr %fiber.control) #0 {
entry:
  %status = call i32 @__bpf_capsule_trampoline_step(i32 %fiber, ptr %fiber.control)
  ret i32 %status
}

define i32 @__bpf_capsule_trampoline(i32 %fiber) #0 {
entry:
  %fiber.control = getelementptr [1 x %fiber_control], ptr @bpf_capsule_fibers, i32 0, i32 %fiber
  %status = call i32 @__bpf_capsule_trampoline_l1(i32 %fiber, ptr %fiber.control)
  ret i32 %status
}

define void @recursive_callee(ptr %output) !bpf.capsule !0 {
entry:
  %value = load i64, ptr %output, align 8
  %again = icmp sgt i64 %value, 0
  br i1 %again, label %recurse, label %done

recurse:                                          ; preds = %entry
  call void @recursive_callee(ptr %output)
  br label %done

done:                                             ; preds = %recurse, %entry
  store i64 42, ptr %output, align 8
  ret void
}

define void @sectioned_pointer_across_call() !bpf.capsule !0 {
entry:
  %output = getelementptr inbounds %control, ptr @sectioned_control, i32 0, i32 1
  call void @recursive_callee(ptr %output)
  ret void
}

define i32 @start(i32 %fiber) section "syscall" !bpf.native !0 {
entry:
  call void @sectioned_pointer_across_call() [ "bpf.capsule.call"(i32 %fiber) ]
  ret i32 0
}

attributes #0 = { "capsule.trampoline" }

!0 = !{}
