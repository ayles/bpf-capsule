source_filename = "stackify-setjmp.c"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpfel"

%fiber_control = type { i32, i32, i64, i64, i64, i32, i32 }
%config = type { i32, i32, i32, i32, i32, i32, i32, i32, i32, i32, i32, i32, i64 }

@bpf_capsule_fibers = global [1 x %fiber_control] zeroinitializer, section ".bss.bpfctrl", align 8
@bpf_capsule_config = constant %config { i32 0, i32 4096, i32 0, i32 0, i32 1, i32 4096, i32 1, i32 0, i32 1, i32 0, i32 1112556353, i32 8, i64 0 }, section ".rodata.bpfconfig", align 4
@bpf_call_stack = internal global [262144 x i8] zeroinitializer, align 262144, !bpf.fiber.stack.size !0

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

define i32 @start(i32 %fiber) section "syscall" !bpf.native !2 {
entry:
  %fiber.index = and i32 %fiber, 0
  %fiber.index1 = and i32 %fiber.index, 0
  %0 = zext i32 %fiber.index1 to i64
  %1 = mul i64 %0, 262144
  %stack.linear.offset = add i64 %1, 262112
  %fiber.stack = getelementptr i8, ptr @bpf_call_stack, i64 %stack.linear.offset
  %root.fp = ptrtoint ptr %fiber.stack to i64
  %fiber.index2 = and i32 %fiber.index, 0
  %fiber.control = getelementptr inbounds [1 x %fiber_control], ptr @bpf_capsule_fibers, i32 0, i32 %fiber.index2, !bpf.capsule.sectioned.bounded !2
  %fiber.outcome = getelementptr inbounds nuw %fiber_control, ptr %fiber.control, i32 0, i32 0
  store i64 0, ptr %fiber.outcome, align 8
  %root.saved.fp = getelementptr i8, ptr %fiber.stack, i64 0
  store i64 0, ptr %root.saved.fp, align 8
  %root.return.pc = getelementptr i8, ptr %fiber.stack, i64 8
  store i32 -1, ptr %root.return.pc, align 4
  %2 = getelementptr i8, ptr %fiber.stack, i64 24
  store i32 37, ptr %2, align 8
  %fiber.index3 = and i32 %fiber.index, 0
  %fiber.control4 = getelementptr inbounds [1 x %fiber_control], ptr @bpf_capsule_fibers, i32 0, i32 %fiber.index3, !bpf.capsule.sectioned.bounded !2
  %fiber.return.size = getelementptr inbounds nuw %fiber_control, ptr %fiber.control4, i32 0, i32 6
  store i32 4, ptr %fiber.return.size, align 4
  %fiber.index5 = and i32 %fiber.index, 0
  %fiber.control6 = getelementptr inbounds [1 x %fiber_control], ptr @bpf_capsule_fibers, i32 0, i32 %fiber.index5, !bpf.capsule.sectioned.bounded !2
  %fiber.pc = getelementptr inbounds nuw %fiber_control, ptr %fiber.control6, i32 0, i32 5
  store i32 256, ptr %fiber.pc, align 4
  %fiber.index7 = and i32 %fiber.index, 0
  %fiber.control8 = getelementptr inbounds [1 x %fiber_control], ptr @bpf_capsule_fibers, i32 0, i32 %fiber.index7, !bpf.capsule.sectioned.bounded !2
  %fiber.sp = getelementptr inbounds nuw %fiber_control, ptr %fiber.control8, i32 0, i32 3
  store i64 %root.fp, ptr %fiber.sp, align 8
  %fiber.index9 = and i32 %fiber.index, 0
  %fiber.control10 = getelementptr inbounds [1 x %fiber_control], ptr @bpf_capsule_fibers, i32 0, i32 %fiber.index9, !bpf.capsule.sectioned.bounded !2
  %fiber.fp = getelementptr inbounds nuw %fiber_control, ptr %fiber.control10, i32 0, i32 4
  store i64 %root.fp, ptr %fiber.fp, align 8
  %control.i = getelementptr [1 x %fiber_control], ptr @bpf_capsule_fibers, i32 0, i32 %fiber.index
  %status.i = call i32 @__bpf_capsule_trampoline_l1(i32 %fiber.index, ptr %control.i)
  %fiber.index11 = and i32 %fiber.index, 0
  %3 = zext i32 %fiber.index11 to i64
  %4 = mul i64 %3, 262144
  %stack.linear.offset12 = add i64 %4, 262128
  %fiber.stack13 = getelementptr i8, ptr @bpf_call_stack, i64 %stack.linear.offset12
  %root.result = load i32, ptr %fiber.stack13, align 8
  ret i32 %root.result
}

; Function Attrs: noinline
define i32 @bpf_capsule_set_outcome(i32 %fiber, i64 %outcome) #1 !bpf.native.scalar !2 {
entry:
  %fiber.index = and i32 %fiber, 0
  %fiber.control = getelementptr inbounds [1 x %fiber_control], ptr @bpf_capsule_fibers, i32 0, i32 %fiber.index, !bpf.capsule.sectioned.bounded !2
  %fiber.outcome = getelementptr inbounds nuw %fiber_control, ptr %fiber.control, i32 0, i32 0
  store volatile i64 %outcome, ptr %fiber.outcome, align 8
  ret i32 0
}

; Function Attrs: noinline
define i32 @__bpf_capsule_trampoline_step(i32 %fiber, ptr "bpf.capsule.control" %fiber_control) #2 !bpf.capsule !2 !bpf.capsule.allocation.unit !3 !bpf.capsule.stack.size !0 {
unit.entry:
  %0 = icmp ne ptr %fiber_control, null
  br i1 %0, label %unit.control.ready, label %unit.control.missing

step.lifecycle:                                   ; preds = %unit.control.ready
  %fiber.pc1 = getelementptr inbounds nuw %fiber_control, ptr %fiber_control, i32 0, i32 5
  %pc = load i32, ptr %fiber.pc1, align 4
  %1 = icmp eq i32 %pc, -1
  %2 = icmp eq i32 %pc, 0
  %3 = or i1 %2, %1
  br i1 %3, label %step.terminal, label %unit.dispatch

step.terminal:                                    ; preds = %step.lifecycle
  br i1 %1, label %step.completed, label %step.stop

step.completed:                                   ; preds = %step.terminal
  store i32 0, ptr %fiber.pc1, align 4
  br label %step.stop

step.stop:                                        ; preds = %step.completed, %step.terminal
  ret i32 1

unit.dispatch:                                    ; preds = %step.lifecycle
  %fiber.pc2 = getelementptr inbounds nuw %fiber_control, ptr %fiber_control, i32 0, i32 5
  %region.counter = load i32, ptr %fiber.pc2, align 4
  %region = and i32 %region.counter, 16776960
  br label %unit.dispatch3

unit.control.ready:                               ; preds = %unit.entry
  %fiber.fp = getelementptr inbounds nuw %fiber_control, ptr %fiber_control, i32 0, i32 4
  %frame.fp = load i64, ptr %fiber.fp, align 8
  %frame.addr = inttoptr i64 %frame.fp to ptr
  call void asm sideeffect "# bpf_capsule_stack_anchor", "r"(ptr %fiber_control)
  br label %step.lifecycle

unit.control.missing:                             ; preds = %unit.entry
  ret i32 1

root.prologue:                                    ; preds = %unit.test.left
  %frame.sp = sub i64 %frame.fp, 48
  %slice.offset = and i64 %frame.fp, 262143
  %4 = icmp ult i64 %slice.offset, 131120
  br i1 %4, label %root.prologue.overflow, label %entry

entry:                                            ; preds = %root.prologue
  %fiber.sp = getelementptr inbounds nuw %fiber_control, ptr %fiber_control, i32 0, i32 3
  store i64 %frame.sp, ptr %fiber.sp, align 8
  %env.slot1 = getelementptr i8, ptr %frame.addr, i64 -48
  %setjmp.slot = getelementptr i8, ptr %frame.addr, i64 -16
  store i32 0, ptr %setjmp.slot, align 4
  %5 = getelementptr i8, ptr %env.slot1, i64 0
  store i32 512, ptr %5, align 4
  %fiber.sp4 = getelementptr inbounds nuw %fiber_control, ptr %fiber_control, i32 0, i32 3
  %6 = load i64, ptr %fiber.sp4, align 8
  %7 = getelementptr i8, ptr %env.slot1, i64 8
  store i64 %6, ptr %7, align 8
  %8 = getelementptr i8, ptr %env.slot1, i64 16
  store i64 %frame.fp, ptr %8, align 8
  %9 = ptrtoint ptr %setjmp.slot to i64
  %10 = getelementptr i8, ptr %env.slot1, i64 24
  store i64 %9, ptr %10, align 8
  br label %entry.setjmp.resume

entry.setjmp.resume:                              ; preds = %unit.test.right, %entry
  %11 = getelementptr i8, ptr %frame.addr, i64 -16
  %setjmp.result = load i32, ptr %11, align 4
  %first = icmp eq i32 %setjmp.result, 0
  br i1 %first, label %jump, label %done

done:                                             ; preds = %entry.setjmp.resume
  %result.slot = getelementptr i8, ptr %frame.addr, i64 16
  store i32 %setjmp.result, ptr %result.slot, align 8
  %12 = getelementptr i8, ptr %frame.addr, i64 8
  %return.pc = load i32, ptr %12, align 4
  %13 = getelementptr i8, ptr %frame.addr, i64 0
  %saved.fp = load i64, ptr %13, align 8
  %fiber.pc = getelementptr inbounds nuw %fiber_control, ptr %fiber_control, i32 0, i32 5
  store i32 %return.pc, ptr %fiber.pc, align 4
  %return.sp = add i64 %frame.fp, 16
  %fiber.sp2 = getelementptr inbounds nuw %fiber_control, ptr %fiber_control, i32 0, i32 3
  store i64 %return.sp, ptr %fiber.sp2, align 8
  %fiber.fp3 = getelementptr inbounds nuw %fiber_control, ptr %fiber_control, i32 0, i32 4
  store i64 %saved.fp, ptr %fiber.fp3, align 8
  ret i32 0

jump:                                             ; preds = %entry.setjmp.resume
  %env.slot = getelementptr i8, ptr %frame.addr, i64 -48
  %14 = getelementptr i8, ptr %frame.addr, i64 24
  %value = load i32, ptr %14, align 4
  %15 = icmp eq i32 %value, 0
  %longjmp.value = select i1 %15, i32 1, i32 %value
  %16 = getelementptr i8, ptr %env.slot, i64 24
  %17 = load i64, ptr %16, align 8
  %18 = inttoptr i64 %17 to ptr
  store i32 %longjmp.value, ptr %18, align 4
  %19 = getelementptr i8, ptr %env.slot, i64 8
  %20 = load i64, ptr %19, align 8
  %fiber.sp5 = getelementptr inbounds nuw %fiber_control, ptr %fiber_control, i32 0, i32 3
  store i64 %20, ptr %fiber.sp5, align 8
  %21 = getelementptr i8, ptr %env.slot, i64 16
  %22 = load i64, ptr %21, align 8
  %fiber.fp6 = getelementptr inbounds nuw %fiber_control, ptr %fiber_control, i32 0, i32 4
  store i64 %22, ptr %fiber.fp6, align 8
  %23 = getelementptr i8, ptr %env.slot, i64 0
  %24 = load i32, ptr %23, align 4
  %fiber.pc7 = getelementptr inbounds nuw %fiber_control, ptr %fiber_control, i32 0, i32 5
  store i32 %24, ptr %fiber.pc7, align 4
  ret i32 0

root.prologue.overflow:                           ; preds = %root.prologue
  %fiber.outcome = getelementptr inbounds nuw %fiber_control, ptr %fiber_control, i32 0, i32 0
  %25 = call i32 @bpf_capsule_set_outcome(i32 %fiber, i64 -30064771069)
  ret i32 1

unit.dispatch3:                                   ; preds = %unit.dispatch
  %26 = icmp ult i32 %region, 512
  br i1 %26, label %unit.test.left, label %unit.test.right

unit.test.left:                                   ; preds = %unit.dispatch3
  br label %root.prologue

unit.test.right:                                  ; preds = %unit.dispatch3
  br label %entry.setjmp.resume
}

attributes #0 = { "capsule.trampoline" }
attributes #1 = { noinline }
attributes #2 = { noinline "capsule.trampoline" }

!llvm.module.flags = !{!1}

!0 = !{i64 262144}
!1 = !{i32 1, !"bpf.capsule.classes", i32 1}
!2 = !{}
!3 = !{i32 0}
