source_filename = "stackify-chunk-budget.ll"
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

; Function Attrs: noinline
define i32 @a_loop(i32 %count) #1 !bpf.capsule !0 {
entry:
  %empty = icmp eq i32 %count, 0
  br i1 %empty, label %exit, label %a_loop.body

a_loop.body:                                      ; preds = %a_loop.body, %entry
  %index = phi i32 [ 0, %entry ], [ %next, %a_loop.body ]
  %next = add i32 %index, 1
  %more = icmp ult i32 %next, %count
  br i1 %more, label %a_loop.body, label %exit

exit:                                             ; preds = %a_loop.body, %entry
  %result = phi i32 [ 0, %entry ], [ %next, %a_loop.body ]
  ret i32 %result
}

; Function Attrs: noinline
define i32 @b_loop(i32 %count) #1 !bpf.capsule !0 {
entry:
  %empty = icmp eq i32 %count, 0
  br i1 %empty, label %exit, label %b_loop.body

b_loop.body:                                      ; preds = %b_loop.body, %entry
  %index = phi i32 [ 0, %entry ], [ %next, %b_loop.body ]
  %next = add i32 %index, 1
  %more = icmp ult i32 %next, %count
  br i1 %more, label %b_loop.body, label %exit

exit:                                             ; preds = %b_loop.body, %entry
  %result = phi i32 [ 0, %entry ], [ %next, %b_loop.body ]
  ret i32 %result
}

; Function Attrs: noinline
define i32 @z_loop(i32 %count) #1 !bpf.capsule !0 {
entry:
  %empty = icmp eq i32 %count, 0
  br i1 %empty, label %exit, label %z_loop.body

z_loop.body:                                      ; preds = %z_loop.body, %entry
  %index = phi i32 [ 0, %entry ], [ %next, %z_loop.body ]
  %next = add i32 %index, 1
  %more = icmp ult i32 %next, %count
  br i1 %more, label %z_loop.body, label %exit

exit:                                             ; preds = %z_loop.body, %entry
  %result = phi i32 [ 0, %entry ], [ %next, %z_loop.body ]
  ret i32 %result
}

; Function Attrs: noinline
define i32 @caller(i32 %count) #1 !bpf.capsule !0 {
entry:
  %a = call i32 @a_loop(i32 %count)
  %b = call i32 @b_loop(i32 %a)
  %z0 = call i32 @z_loop(i32 %b)
  %z1 = call i32 @z_loop(i32 %z0)
  %z2 = call i32 @z_loop(i32 %z1)
  %z3 = call i32 @z_loop(i32 %z2)
  %z4 = call i32 @z_loop(i32 %z3)
  %z5 = call i32 @z_loop(i32 %z4)
  %z6 = call i32 @z_loop(i32 %z5)
  %z7 = call i32 @z_loop(i32 %z6)
  ret i32 %z7
}

define i32 @start(i32 %fiber) section "syscall" !bpf.native !0 {
entry:
  %result = call i32 @caller(i32 100) [ "bpf.capsule.call"(i32 %fiber) ]
  ret i32 %result
}

attributes #0 = { "capsule.trampoline" }
attributes #1 = { noinline }

!0 = !{}
