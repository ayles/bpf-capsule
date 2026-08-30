source_filename = "stackify-single-use-inline.c"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpfel"

%fiber_control = type { i32, i32, i64, i64, i64, i32, i32 }
%config = type { i32, i32, i32, i32, i32, i32, i32, i32, i32, i32, i32, i32, i64 }

@bpf_capsule_fibers = global [1 x %fiber_control] zeroinitializer, section ".bss.bpfctrl", align 8
@bpf_capsule_config = constant %config { i32 0, i32 4096, i32 0, i32 0, i32 1, i32 4096, i32 1, i32 0, i32 1, i32 0, i32 1112556353, i32 5, i64 0 }, section ".rodata.bpfconfig", align 4

declare i32 @__bpf_capsule_trampoline_step(i32, ptr)

declare void @__bpf_capsule_yield()

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

define i32 @small_helper(i32 %value) !bpf.capsule !0 {
entry:
  %result = mul i32 %value, 3
  ret i32 %result
}

; Function Attrs: noinline
define i32 @policy_noinline(i32 %value) #1 !bpf.capsule !0 {
entry:
  %result = sub i32 %value, 2
  ret i32 %result
}

; Function Attrs: noinline
define i32 @explicit_noinline(i32 %value) #2 !bpf.capsule !0 {
entry:
  %result = add i32 %value, 1
  ret i32 %result
}

define i32 @root(i32 %value) !bpf.capsule !0 {
entry:
  call void @__bpf_capsule_yield()
  %result = call i32 @small_helper(i32 %value)
  %reconsidered = call i32 @policy_noinline(i32 %result)
  %kept = call i32 @explicit_noinline(i32 %reconsidered)
  ret i32 %kept
}

define i32 @start(i32 %fiber) section "syscall" !bpf.native !0 {
entry:
  %result = call i32 @root(i32 14) [ "bpf.capsule.call"(i32 %fiber) ]
  ret i32 %result
}

attributes #0 = { "capsule.trampoline" }
attributes #1 = { noinline "bpf.capsule.inline-policy-veto" }
attributes #2 = { noinline }

!0 = !{}
