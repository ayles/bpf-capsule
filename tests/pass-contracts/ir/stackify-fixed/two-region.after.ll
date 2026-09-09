source_filename = "stackify-fixed-contract.c"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpfel"

%fiber_control = type { i32, i32, i64, i64, i64, i32, i32 }
%config = type { i32, i32, i32, i32, i32, i32, i32, i32, i32, i32, i32, i32, i64 }

@bpf_capsule_fibers = global [1 x %fiber_control] zeroinitializer, section ".bss.bpfctrl", align 8
@bpf_capsule_config = constant %config { i32 0, i32 4096, i32 0, i32 0, i32 1, i32 4096, i32 1, i32 0, i32 0, i32 0, i32 1112556353, i32 8, i64 0 }, section ".rodata.bpfconfig", align 4
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
  %stack.linear.offset = add i64 %1, 262112
  %fiber.stack = getelementptr i8, ptr @bpf_call_stack, i64 %stack.linear.offset
  %root.fp = ptrtoint ptr %fiber.stack to i64
  %fiber.index2 = and i32 %fiber.index, 0
  %fiber.control = getelementptr inbounds [1 x %fiber_control], ptr @bpf_capsule_fibers, i32 0, i32 %fiber.index2, !bpf.capsule.sectioned.bounded !2
  %fiber.outcome = getelementptr inbounds nuw %fiber_control, ptr %fiber.control, i32 0, i32 0
  store i64 0, ptr %fiber.outcome, align 8
  %root.saved.fp = getelementptr i8, ptr %fiber.stack, i64 0
  store i64 0, ptr %root.saved.fp, align 8
  %root.return.region.id = getelementptr i8, ptr %fiber.stack, i64 8
  store i32 -1, ptr %root.return.region.id, align 4
  %2 = getelementptr i8, ptr %fiber.stack, i64 24
  store i32 41, ptr %2, align 8
  %fiber.index3 = and i32 %fiber.index, 0
  %fiber.control4 = getelementptr inbounds [1 x %fiber_control], ptr @bpf_capsule_fibers, i32 0, i32 %fiber.index3, !bpf.capsule.sectioned.bounded !2
  %fiber.return.size = getelementptr inbounds nuw %fiber_control, ptr %fiber.control4, i32 0, i32 6
  store i32 4, ptr %fiber.return.size, align 4
  %fiber.index5 = and i32 %fiber.index, 0
  %fiber.control6 = getelementptr inbounds [1 x %fiber_control], ptr @bpf_capsule_fibers, i32 0, i32 %fiber.index5, !bpf.capsule.sectioned.bounded !2
  %fiber.resume.region.id = getelementptr inbounds nuw %fiber_control, ptr %fiber.control6, i32 0, i32 5
  store i32 256, ptr %fiber.resume.region.id, align 4
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
define i32 @bpf.unit.0(i32 %fiber, ptr "bpf.capsule.control" %fiber_control, ptr "bpf.capsule.stack.backing" %stack_base, i32 %region) #1 !bpf.capsule !2 !bpf.capsule.allocation.unit !3 !bpf.capsule.stack.size !0 !bpf.capsule.flatten.unit !4 {
unit.entry:
  %fiber.fp = getelementptr inbounds nuw %fiber_control, ptr %fiber_control, i32 0, i32 4
  %frame.fp = load i64, ptr %fiber.fp, align 8
  %fiber.index = and i32 %fiber, 0
  %stack.offset = and i64 %frame.fp, 262143
  %0 = zext i32 %fiber.index to i64
  %1 = mul i64 %0, 262144
  %stack.linear.offset = add i64 %1, %stack.offset
  %fiber.stack = getelementptr i8, ptr @bpf_call_stack, i64 %stack.linear.offset
  call void asm sideeffect "# bpf_capsule_stack_anchor", "r"(ptr %stack_base)
  br label %unit.dispatch

unit.dispatch:                                    ; preds = %unit.entry
  br label %unit.dispatch1

root.prologue:                                    ; preds = %unit.test.left
  %frame.sp = sub i64 %frame.fp, 0
  %slice.offset = and i64 %frame.fp, 262143
  %2 = icmp ult i64 %slice.offset, 131072
  br i1 %2, label %root.prologue.overflow, label %entry

entry:                                            ; preds = %root.prologue
  %fiber.sp = getelementptr inbounds nuw %fiber_control, ptr %fiber_control, i32 0, i32 3
  store i64 %frame.sp, ptr %fiber.sp, align 8
  %fiber.resume.region.id5 = getelementptr inbounds nuw %fiber_control, ptr %fiber_control, i32 0, i32 5
  store i32 512, ptr %fiber.resume.region.id5, align 4
  %fiber.outcome6 = getelementptr inbounds nuw %fiber_control, ptr %fiber_control, i32 0, i32 0
  store i64 2, ptr %fiber.outcome6, align 8
  ret i32 1

root.prologue.overflow:                           ; preds = %root.prologue
  %fiber.outcome = getelementptr inbounds nuw %fiber_control, ptr %fiber_control, i32 0, i32 0
  %3 = call i32 @bpf_capsule_set_outcome(i32 %fiber, i64 -30064771069)
  ret i32 1

entry.yield.resume:                               ; preds = %unit.test.right
  %4 = getelementptr i8, ptr %fiber.stack, i64 24
  %value = load i32, ptr %4, align 4
  %result = add i32 %value, 1
  %result.slot = getelementptr i8, ptr %fiber.stack, i64 16
  store i32 %result, ptr %result.slot, align 8
  %5 = getelementptr i8, ptr %fiber.stack, i64 8
  %return.region.id = load i32, ptr %5, align 4
  %6 = getelementptr i8, ptr %fiber.stack, i64 0
  %saved.fp = load i64, ptr %6, align 8
  %fiber.resume.region.id = getelementptr inbounds nuw %fiber_control, ptr %fiber_control, i32 0, i32 5
  store i32 %return.region.id, ptr %fiber.resume.region.id, align 4
  %return.sp = add i64 %frame.fp, 16
  %fiber.sp3 = getelementptr inbounds nuw %fiber_control, ptr %fiber_control, i32 0, i32 3
  store i64 %return.sp, ptr %fiber.sp3, align 8
  %fiber.fp4 = getelementptr inbounds nuw %fiber_control, ptr %fiber_control, i32 0, i32 4
  store i64 %saved.fp, ptr %fiber.fp4, align 8
  ret i32 0

unit.dispatch1:                                   ; preds = %unit.dispatch
  %7 = icmp ult i32 %region, 512
  br i1 %7, label %unit.test.left, label %unit.test.right

unit.test.left:                                   ; preds = %unit.dispatch1
  br label %root.prologue

unit.test.right:                                  ; preds = %unit.dispatch1
  br label %entry.yield.resume
}

; Function Attrs: noinline
define i32 @__bpf_capsule_trampoline_step(i32 %fiber, ptr "bpf.capsule.control" %fiber_control, ptr "bpf.capsule.stack.backing" %stack_base) #2 {
entry:
  %0 = icmp ne ptr %fiber_control, null
  br i1 %0, label %control.ready, label %control.missing

stack.ready:                                      ; preds = %control.ready
  br label %iterate

stack.missing:                                    ; preds = %control.ready
  %1 = call i32 @bpf_capsule_set_outcome(i32 %fiber, i64 -34359738365)
  ret i32 1

iterate:                                          ; preds = %latch, %stack.ready
  %trip = phi i32 [ 0, %stack.ready ], [ %trip.next, %latch ]
  %fiber.resume.region.id = getelementptr inbounds nuw %fiber_control, ptr %fiber_control, i32 0, i32 5
  %resume.region.id = load i32, ptr %fiber.resume.region.id, align 4
  %2 = icmp eq i32 %resume.region.id, -1
  %3 = icmp eq i32 %resume.region.id, 0
  %4 = or i1 %3, %2
  br label %route

control.ready:                                    ; preds = %entry
  %5 = icmp ne ptr %stack_base, null
  br i1 %5, label %stack.ready, label %stack.missing

control.missing:                                  ; preds = %entry
  ret i32 1

route:                                            ; preds = %iterate
  br label %dispatch

dispatch:                                         ; preds = %route
  %step.index = and i32 %resume.region.id, 255
  %region.key = and i32 %resume.region.id, 16776960
  switch i32 %step.index, label %bad.id [
    i32 0, label %idle.or.root
    i32 255, label %completed
  ]

idle.or.root:                                     ; preds = %dispatch
  br i1 %3, label %done, label %bpf.dispatch.output.scalar.0

bpf.dispatch.output.scalar.0:                     ; preds = %idle.or.root
  %6 = call i32 @bpf.dispatch.output.scalar.0(i32 %fiber, ptr %fiber_control, ptr %stack_base, i32 %region.key)
  %7 = icmp ne i32 %6, 0
  br i1 %7, label %bpf.dispatch.output.scalar.0.stop, label %latch

bpf.dispatch.output.scalar.0.stop:                ; preds = %bpf.dispatch.output.scalar.0
  ret i32 %6

terminal:                                         ; No predecessors!
  br i1 %2, label %completed, label %done

completed:                                        ; preds = %terminal, %dispatch
  store i32 0, ptr %fiber.resume.region.id, align 4
  br label %done

done:                                             ; preds = %completed, %terminal, %idle.or.root
  ret i32 1

bad.id:                                           ; preds = %dispatch
  %8 = call i32 @bpf_capsule_set_outcome(i32 %fiber, i64 -38654705661)
  ret i32 1

latch:                                            ; preds = %bpf.dispatch.output.scalar.0
  %trip.next = add i32 %trip, 1
  %9 = icmp ult i32 %trip.next, 32
  br i1 %9, label %iterate, label %exhausted

exhausted:                                        ; preds = %latch
  ret i32 0
}

; Function Attrs: noinline
define i32 @bpf.dispatch.output.scalar.0(i32 %fiber, ptr "bpf.capsule.control" %fiber_control, ptr "bpf.capsule.stack.backing" %stack_base, i32 %region) #1 !bpf.capsule.flatten.root !4 {
entry:
  %0 = icmp ne ptr %fiber_control, null
  br i1 %0, label %stack.check, label %bad.id

stack.check:                                      ; preds = %entry
  %1 = icmp ne ptr %stack_base, null
  br i1 %1, label %dispatch, label %bad.id

dispatch:                                         ; preds = %stack.check
  br label %unit.route

unit.route:                                       ; preds = %dispatch
  br label %bpf.unit.0

bad.id:                                           ; preds = %stack.check, %entry
  %2 = call i32 @bpf_capsule_set_outcome(i32 %fiber, i64 -38654705661)
  ret i32 1

bpf.unit.0:                                       ; preds = %unit.route
  %3 = call i32 @bpf.unit.0(i32 %fiber, ptr %fiber_control, ptr %stack_base, i32 %region)
  ret i32 %3
}

attributes #0 = { "capsule.trampoline" }
attributes #1 = { noinline }
attributes #2 = { noinline "capsule.trampoline" }

!llvm.module.flags = !{!1}

!0 = !{i64 262144}
!1 = !{i32 1, !"bpf.capsule.classes", i32 1}
!2 = !{}
!3 = !{i32 0}
!4 = !{i32 2}
