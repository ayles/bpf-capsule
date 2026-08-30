source_filename = "stackify-virtualized-loop.ll"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpfel"

%fiber_control = type { i32, i32, i64, i64, i64, i32, i32 }
%config = type { i32, i32, i32, i32, i32, i32, i32, i32, i32, i32, i32, i32, i64 }

@bpf_capsule_fibers = global [1 x %fiber_control] zeroinitializer, section ".bss.bpfctrl", align 8
@bpf_capsule_config = constant %config { i32 0, i32 4096, i32 0, i32 0, i32 1, i32 4096, i32 1, i32 0, i32 1, i32 0, i32 1112556353, i32 5, i64 0 }, section ".rodata.bpfconfig", align 4
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
  %stack.linear.offset = add i64 %1, 262128
  %fiber.stack = getelementptr i8, ptr @bpf_call_stack, i64 %stack.linear.offset
  %root.fp = ptrtoint ptr %fiber.stack to i64
  %fiber.index2 = and i32 %fiber.index, 0
  %fiber.control = getelementptr inbounds [1 x %fiber_control], ptr @bpf_capsule_fibers, i32 0, i32 %fiber.index2, !bpf.capsule.sectioned.bounded !2
  %fiber.outcome = getelementptr inbounds nuw %fiber_control, ptr %fiber.control, i32 0, i32 0
  store i64 0, ptr %fiber.outcome, align 8
  %root.return.pc = getelementptr i8, ptr %fiber.stack, i64 -8
  store i32 -1, ptr %root.return.pc, align 4
  %root.saved.fp = getelementptr i8, ptr %fiber.stack, i64 -16
  store i64 0, ptr %root.saved.fp, align 8
  %2 = getelementptr i8, ptr %fiber.stack, i64 -24
  store i32 100, ptr %2, align 4
  %fiber.index3 = and i32 %fiber.index, 0
  %fiber.control4 = getelementptr inbounds [1 x %fiber_control], ptr @bpf_capsule_fibers, i32 0, i32 %fiber.index3, !bpf.capsule.sectioned.bounded !2
  %fiber.return.size = getelementptr inbounds nuw %fiber_control, ptr %fiber.control4, i32 0, i32 6
  store i32 4, ptr %fiber.return.size, align 4
  %fiber.index5 = and i32 %fiber.index, 0
  %fiber.control6 = getelementptr inbounds [1 x %fiber_control], ptr @bpf_capsule_fibers, i32 0, i32 %fiber.index5, !bpf.capsule.sectioned.bounded !2
  %fiber.pc = getelementptr inbounds nuw %fiber_control, ptr %fiber.control6, i32 0, i32 5
  store i32 1, ptr %fiber.pc, align 4
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
  %root.result = load i32, ptr %fiber.stack13, align 4
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
  br i1 %0, label %step.lifecycle, label %unit.control.missing

step.lifecycle:                                   ; preds = %unit.entry
  %fiber.pc1 = getelementptr inbounds nuw %fiber_control, ptr %fiber_control, i32 0, i32 5
  %pc = load i32, ptr %fiber.pc1, align 4
  %1 = icmp eq i32 %pc, -1
  %fiber.outcome2 = getelementptr inbounds nuw %fiber_control, ptr %fiber_control, i32 0, i32 0
  %2 = load i64, ptr %fiber.outcome2, align 8
  %3 = icmp ne i64 %2, 0
  %4 = icmp eq i32 %pc, 0
  %5 = or i1 %1, %3
  %6 = or i1 %4, %5
  br i1 %6, label %step.terminal, label %unit.control.ready

step.terminal:                                    ; preds = %step.lifecycle
  br i1 %1, label %step.completed, label %step.stop

step.completed:                                   ; preds = %step.terminal
  store i32 0, ptr %fiber.pc1, align 4
  br label %step.stop

step.stop:                                        ; preds = %step.completed, %step.terminal
  ret i32 1

unit.control.ready:                               ; preds = %step.lifecycle
  %fiber.fp = getelementptr inbounds nuw %fiber_control, ptr %fiber_control, i32 0, i32 4
  %frame.fp = load i64, ptr %fiber.fp, align 8
  %frame.addr = inttoptr i64 %frame.fp to ptr
  %fiber.index = and i32 %fiber, 0
  %7 = zext i32 %fiber.index to i64
  %8 = mul i64 %7, 262144
  %stack.linear.offset = add i64 %8, 0
  %fiber.stack = getelementptr i8, ptr @bpf_call_stack, i64 %stack.linear.offset
  call void asm sideeffect "# bpf_capsule_stack_anchor", "r"(ptr %fiber.stack)
  %fiber.pc3 = getelementptr inbounds nuw %fiber_control, ptr %fiber_control, i32 0, i32 5
  %pc4 = load i32, ptr %fiber.pc3, align 4
  %9 = icmp ult i32 %pc4, 2
  br i1 %9, label %unit.test.left, label %unit.test.right

unit.control.missing:                             ; preds = %unit.entry
  ret i32 1

virtualized_loop.prologue:                        ; preds = %unit.test.left
  %frame.sp = sub i64 %frame.fp, 48
  %slice.offset = and i64 %frame.fp, 262143
  %10 = icmp ult i64 %slice.offset, 131152
  br i1 %10, label %virtualized_loop.prologue.overflow, label %entry

entry:                                            ; preds = %virtualized_loop.prologue
  %fiber.sp = getelementptr inbounds nuw %fiber_control, ptr %fiber_control, i32 0, i32 3
  store i64 %frame.sp, ptr %fiber.sp, align 8
  %index.reg2mem.slot2 = getelementptr i8, ptr %frame.addr, i64 -48
  store i32 0, ptr %index.reg2mem.slot2, align 4
  br label %loop

loop:                                             ; preds = %unit.test.right, %entry
  %index.reg2mem.slot = getelementptr i8, ptr %frame.addr, i64 -48
  %index.reload = load i32, ptr %index.reg2mem.slot, align 4
  call void asm sideeffect "r0 = r0", ""()
  %next = add i32 %index.reload, 1
  %11 = getelementptr i8, ptr %frame.addr, i64 -24
  %count = load i32, ptr %11, align 4
  %more = icmp ult i32 %next, %count
  br i1 %more, label %loop.loop_crit_edge, label %exit

exit:                                             ; preds = %loop
  store i32 %next, ptr %frame.addr, align 4
  %12 = getelementptr i8, ptr %frame.addr, i64 -8
  %return.pc = load i32, ptr %12, align 4
  %13 = getelementptr i8, ptr %frame.addr, i64 -16
  %saved.fp = load i64, ptr %13, align 8
  %fiber.pc = getelementptr inbounds nuw %fiber_control, ptr %fiber_control, i32 0, i32 5
  store i32 %return.pc, ptr %fiber.pc, align 4
  %fiber.sp3 = getelementptr inbounds nuw %fiber_control, ptr %fiber_control, i32 0, i32 3
  store i64 %frame.fp, ptr %fiber.sp3, align 8
  %fiber.fp4 = getelementptr inbounds nuw %fiber_control, ptr %fiber_control, i32 0, i32 4
  store i64 %saved.fp, ptr %fiber.fp4, align 8
  ret i32 0

loop.loop_crit_edge:                              ; preds = %loop
  %index.reg2mem.slot1 = getelementptr i8, ptr %frame.addr, i64 -48
  store i32 %next, ptr %index.reg2mem.slot1, align 4
  %fiber.pc5 = getelementptr inbounds nuw %fiber_control, ptr %fiber_control, i32 0, i32 5
  store i32 2, ptr %fiber.pc5, align 4
  ret i32 0

virtualized_loop.prologue.overflow:               ; preds = %virtualized_loop.prologue
  %fiber.outcome = getelementptr inbounds nuw %fiber_control, ptr %fiber_control, i32 0, i32 0
  %14 = call i32 @bpf_capsule_set_outcome(i32 %fiber, i64 -30064771069)
  ret i32 0

unit.test.left:                                   ; preds = %unit.control.ready
  %15 = icmp eq i32 %pc4, 1
  br i1 %15, label %virtualized_loop.prologue, label %unit.unknown

unit.test.right:                                  ; preds = %unit.control.ready
  %16 = icmp eq i32 %pc4, 2
  br i1 %16, label %loop, label %unit.unknown

unit.unknown:                                     ; preds = %unit.test.right, %unit.test.left
  %17 = call i32 @bpf_capsule_set_outcome(i32 %fiber, i64 -38654705661)
  ret i32 0
}

attributes #0 = { "capsule.trampoline" }
attributes #1 = { noinline }
attributes #2 = { noinline "capsule.trampoline" }

!llvm.module.flags = !{!1}

!0 = !{i64 262144}
!1 = !{i32 1, !"bpf.capsule.classes", i32 1}
!2 = !{}
!3 = !{i32 0}
