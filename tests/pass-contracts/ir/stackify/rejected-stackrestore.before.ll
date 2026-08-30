source_filename = "stackify-rejected-stackrestore.ll"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpfel"

%fiber_control = type { i32, i32, i64, i64, i64, i32, i32 }
%config = type { i32, i32, i32, i32, i32, i32, i32, i32, i32, i32, i32, i32, i64 }

@bpf_capsule_fibers = global [1 x %fiber_control] zeroinitializer, section ".bss.bpfctrl", align 8
@bpf_capsule_config = constant %config { i32 0, i32 4096, i32 0, i32 0, i32 1, i32 4096, i32 1, i32 0, i32 1, i32 0, i32 1112556353, i32 5, i64 0 }, section ".rodata.bpfconfig", align 4

declare i32 @__bpf_capsule_trampoline_step(i32, ptr)

; Function Attrs: nocallback nofree nosync nounwind willreturn
declare void @llvm.stackrestore.p0(ptr) #0

define i32 @__bpf_capsule_trampoline_l1(i32 %fiber, ptr %control) #1 {
entry:
  %status = call i32 @__bpf_capsule_trampoline_step(i32 %fiber, ptr %control)
  ret i32 %status
}

define i32 @__bpf_capsule_trampoline(i32 %fiber) #1 {
entry:
  %control = getelementptr [1 x %fiber_control], ptr @bpf_capsule_fibers, i32 0, i32 %fiber
  %status = call i32 @__bpf_capsule_trampoline_l1(i32 %fiber, ptr %control)
  ret i32 %status
}

define i32 @root() !bpf.capsule !0 {
entry:
  %not_a_save = alloca i8, align 1
  call void @llvm.stackrestore.p0(ptr %not_a_save)
  ret i32 7
}

define i32 @start(i32 %fiber) section "syscall" !bpf.native !0 {
entry:
  %result = call i32 @root() [ "bpf.capsule.call"(i32 %fiber) ]
  ret i32 %result
}

attributes #0 = { nocallback nofree nosync nounwind willreturn }
attributes #1 = { "capsule.trampoline" }

!0 = !{}
