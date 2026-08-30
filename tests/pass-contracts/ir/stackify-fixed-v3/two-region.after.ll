source_filename = "stackify-fixed-contract.c"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpfel"

%fiber_control = type { i32, i32, i64, i64, i64, i32, i32 }
%config = type { i32, i32, i32, i32, i32, i32, i32, i32, i32, i32, i32, i32, i64 }

@bpf_capsule_fibers = global [1 x %fiber_control] zeroinitializer, section ".bss.bpfctrl", align 8
@bpf_capsule_config = constant %config { i32 0, i32 4096, i32 0, i32 0, i32 1, i32 4096, i32 1, i32 0, i32 0, i32 0, i32 1112556353, i32 5, i64 0 }, section ".rodata.bpfconfig", align 4
@bpf_call_stack = internal global [262144 x i8] zeroinitializer, align 262144, !bpf.fiber.stack.size !0

declare ptr @__bpf_capsule_stack_region(i32)

define i32 @__bpf_capsule_trampoline_l1(i32 %fiber, ptr %control, ptr %stack.base) #0 {
entry:
  %status = call i32 @__bpf_capsule_trampoline_step(i32 %fiber, ptr %control, ptr %stack.base)
  ret i32 %status
}

define i32 @__bpf_capsule_trampoline(i32 %fiber) #0 {
entry:
  %control = getelementptr [1 x %fiber_control], ptr @bpf_capsule_fibers, i32 0, i32 %fiber
  %stack.base = call ptr @__bpf_capsule_stack_region(i32 %fiber)
  %status = call i32 @__bpf_capsule_trampoline_l1(i32 %fiber, ptr %control, ptr %stack.base)
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
  store i32 41, ptr %2, align 4
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
  %stack.base.i = call ptr @__bpf_capsule_stack_region(i32 %fiber.index)
  %status.i = call i32 @__bpf_capsule_trampoline_l1(i32 %fiber.index, ptr %control.i, ptr %stack.base.i)
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
define i32 @__bpf_capsule_trampoline_step(i32 %fiber, ptr "bpf.capsule.control" %fiber_control, ptr "bpf.capsule.stack.backing" %stack_base) #2 !bpf.capsule !2 !bpf.capsule.allocation.unit !3 !bpf.capsule.stack.size !0 {
unit.entry:
  %0 = icmp ne ptr %fiber_control, null
  br i1 %0, label %unit.control.ready, label %unit.control.missing

unit.control.ready:                               ; preds = %unit.entry
  %1 = icmp ne ptr %stack_base, null
  br i1 %1, label %step.lifecycle, label %unit.stack.missing

unit.control.missing:                             ; preds = %unit.entry
  ret i32 1

step.lifecycle:                                   ; preds = %unit.control.ready
  %fiber.pc2 = getelementptr inbounds nuw %fiber_control, ptr %fiber_control, i32 0, i32 5
  %pc = load i32, ptr %fiber.pc2, align 4
  %2 = icmp eq i32 %pc, -1
  %fiber.outcome3 = getelementptr inbounds nuw %fiber_control, ptr %fiber_control, i32 0, i32 0
  %3 = load i64, ptr %fiber.outcome3, align 8
  %4 = icmp ne i64 %3, 0
  %5 = icmp eq i32 %pc, 0
  %6 = or i1 %2, %4
  %7 = or i1 %5, %6
  br i1 %7, label %step.terminal, label %unit.stack.ready

step.terminal:                                    ; preds = %step.lifecycle
  br i1 %2, label %step.completed, label %step.stop

step.completed:                                   ; preds = %step.terminal
  store i32 0, ptr %fiber.pc2, align 4
  br label %step.stop

step.stop:                                        ; preds = %step.completed, %step.terminal
  ret i32 1

unit.stack.ready:                                 ; preds = %step.lifecycle
  %fiber.fp = getelementptr inbounds nuw %fiber_control, ptr %fiber_control, i32 0, i32 4
  %frame.fp = load i64, ptr %fiber.fp, align 8
  %fiber.index = and i32 %fiber, 0
  %stack.offset = and i64 %frame.fp, 262143
  %8 = zext i32 %fiber.index to i64
  %9 = mul i64 %8, 262144
  %stack.linear.offset = add i64 %9, %stack.offset
  %fiber.stack = getelementptr i8, ptr @bpf_call_stack, i64 %stack.linear.offset
  call void asm sideeffect "# bpf_capsule_stack_anchor", "r"(ptr %stack_base)
  %fiber.pc4 = getelementptr inbounds nuw %fiber_control, ptr %fiber_control, i32 0, i32 5
  %pc5 = load i32, ptr %fiber.pc4, align 4
  %10 = icmp ult i32 %pc5, 2
  br i1 %10, label %unit.test.left, label %unit.test.right

unit.stack.missing:                               ; preds = %unit.control.ready
  %fiber.outcome = getelementptr inbounds nuw %fiber_control, ptr %fiber_control, i32 0, i32 0
  %11 = call i32 @bpf_capsule_set_outcome(i32 %fiber, i64 -34359738365)
  ret i32 1

root.prologue:                                    ; preds = %unit.test.left
  %frame.sp = sub i64 %frame.fp, 32
  %slice.offset = and i64 %frame.fp, 262143
  %12 = icmp ult i64 %slice.offset, 131136
  br i1 %12, label %root.prologue.overflow, label %entry

entry:                                            ; preds = %root.prologue
  %fiber.sp = getelementptr inbounds nuw %fiber_control, ptr %fiber_control, i32 0, i32 3
  store i64 %frame.sp, ptr %fiber.sp, align 8
  %fiber.pc5 = getelementptr inbounds nuw %fiber_control, ptr %fiber_control, i32 0, i32 5
  store i32 2, ptr %fiber.pc5, align 4
  %fiber.outcome6 = getelementptr inbounds nuw %fiber_control, ptr %fiber_control, i32 0, i32 0
  store i64 2, ptr %fiber.outcome6, align 8
  ret i32 1

root.prologue.overflow:                           ; preds = %root.prologue
  %fiber.outcome1 = getelementptr inbounds nuw %fiber_control, ptr %fiber_control, i32 0, i32 0
  %13 = call i32 @bpf_capsule_set_outcome(i32 %fiber, i64 -30064771069)
  ret i32 0

entry.yield.resume:                               ; preds = %unit.test.right
  %14 = getelementptr i8, ptr %fiber.stack, i64 -24
  %value = load i32, ptr %14, align 4
  %result = add i32 %value, 1
  store i32 %result, ptr %fiber.stack, align 4
  %15 = getelementptr i8, ptr %fiber.stack, i64 -8
  %return.pc = load i32, ptr %15, align 4
  %16 = getelementptr i8, ptr %fiber.stack, i64 -16
  %saved.fp = load i64, ptr %16, align 8
  %fiber.pc = getelementptr inbounds nuw %fiber_control, ptr %fiber_control, i32 0, i32 5
  store i32 %return.pc, ptr %fiber.pc, align 4
  %fiber.sp3 = getelementptr inbounds nuw %fiber_control, ptr %fiber_control, i32 0, i32 3
  store i64 %frame.fp, ptr %fiber.sp3, align 8
  %fiber.fp4 = getelementptr inbounds nuw %fiber_control, ptr %fiber_control, i32 0, i32 4
  store i64 %saved.fp, ptr %fiber.fp4, align 8
  ret i32 0

unit.test.left:                                   ; preds = %unit.stack.ready
  %17 = icmp eq i32 %pc5, 1
  br i1 %17, label %root.prologue, label %unit.unknown

unit.test.right:                                  ; preds = %unit.stack.ready
  %18 = icmp eq i32 %pc5, 2
  br i1 %18, label %entry.yield.resume, label %unit.unknown

unit.unknown:                                     ; preds = %unit.test.right, %unit.test.left
  %19 = call i32 @bpf_capsule_set_outcome(i32 %fiber, i64 -38654705661)
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
