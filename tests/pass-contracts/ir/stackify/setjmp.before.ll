source_filename = "stackify-setjmp.c"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpfel"

%fiber_control = type { i32, i32, i64, i64, i64, i32, i32 }
%config = type { i32, i32, i32, i32, i32, i32, i32, i32, i32, i32, i32, i32, i64 }

@bpf_capsule_fibers = global [1 x %fiber_control] zeroinitializer, section ".bss.bpfctrl", align 8
@bpf_capsule_config = constant %config { i32 0, i32 4096, i32 0, i32 0, i32 1, i32 4096, i32 1, i32 0, i32 1, i32 0, i32 1112556353, i32 5, i64 0 }, section ".rodata.bpfconfig", align 4

declare i32 @__bpf_capsule_trampoline_step(i32, ptr)

; Function Attrs: returns_twice
declare i32 @__bpf_capsule_setjmp(ptr) #0

; Function Attrs: noreturn
declare void @__bpf_capsule_longjmp(ptr, i32) #1

define i32 @__bpf_capsule_trampoline_l1(i32 %fiber, ptr %control) #2 {
entry:
  %status = call i32 @__bpf_capsule_trampoline_step(i32 %fiber, ptr %control)
  ret i32 %status
}

define i32 @__bpf_capsule_trampoline(i32 %fiber) #2 {
entry:
  %control = getelementptr [1 x %fiber_control], ptr @bpf_capsule_fibers, i32 0, i32 %fiber
  %status = call i32 @__bpf_capsule_trampoline_l1(i32 %fiber, ptr %control)
  ret i32 %status
}

define i32 @root(i32 %value) !bpf.capsule !0 {
entry:
  %env = alloca [4 x i64], align 8
  %result = call i32 @__bpf_capsule_setjmp(ptr %env)
  %first = icmp eq i32 %result, 0
  br i1 %first, label %jump, label %done

jump:                                             ; preds = %entry
  call void @__bpf_capsule_longjmp(ptr %env, i32 %value)
  unreachable

done:                                             ; preds = %entry
  ret i32 %result
}

define i32 @start(i32 %fiber) section "syscall" !bpf.native !0 {
entry:
  %result = call i32 @root(i32 37) [ "bpf.capsule.call"(i32 %fiber) ]
  ret i32 %result
}

attributes #0 = { returns_twice }
attributes #1 = { noreturn }
attributes #2 = { "capsule.trampoline" }

!0 = !{}
