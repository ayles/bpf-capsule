source_filename = "stackify-terminating-helper.ll"
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
  %root.return.region.id = getelementptr i8, ptr %fiber.stack, i64 8
  store i32 -1, ptr %root.return.region.id, align 4
  %2 = getelementptr i8, ptr %fiber.stack, i64 24
  store i1 false, ptr %2, align 8
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
define i32 @bpf.unit.0(i32 %fiber, ptr "bpf.capsule.control" %fiber_control, i32 %region) #1 !bpf.capsule !2 !bpf.capsule.allocation.unit !3 !bpf.capsule.stack.size !0 !bpf.capsule.flatten.unit !4 {
unit.entry:
  %fiber.fp = getelementptr inbounds nuw %fiber_control, ptr %fiber_control, i32 0, i32 4
  %frame.fp = load i64, ptr %fiber.fp, align 8
  %frame.addr = inttoptr i64 %frame.fp to ptr
  call void asm sideeffect "# bpf_capsule_stack_anchor", "r"(ptr %fiber_control)
  br label %unit.dispatch

unit.dispatch:                                    ; preds = %unit.entry
  br label %unit.dispatch2

root.prologue:                                    ; preds = %unit.test.left
  %frame.sp = sub i64 %frame.fp, 16
  %slice.offset = and i64 %frame.fp, 262143
  %0 = icmp ult i64 %slice.offset, 131120
  br i1 %0, label %root.prologue.overflow, label %entry

entry:                                            ; preds = %root.prologue
  %fiber.sp = getelementptr inbounds nuw %fiber_control, ptr %fiber_control, i32 0, i32 3
  store i64 %frame.sp, ptr %fiber.sp, align 8
  %1 = getelementptr i8, ptr %frame.addr, i64 24
  %fail = load i1, ptr %1, align 1
  br i1 %fail, label %outcome.i, label %ordinary.i

ordinary.i:                                       ; preds = %entry
  br label %mixed_terminating_helper.exit

mixed_terminating_helper.exit:                    ; preds = %ordinary.i
  %2 = getelementptr i8, ptr %frame.addr, i64 24
  %fail2 = load i1, ptr %2, align 1
  %caller.sp = sub i64 %frame.fp, 16
  %callee.fp = sub i64 %caller.sp, 32
  %callee.frame = getelementptr i8, ptr %frame.addr, i64 -48
  %saved.fp.slot = getelementptr i8, ptr %callee.frame, i64 0
  store i64 %frame.fp, ptr %saved.fp.slot, align 8
  %return.region.id.slot = getelementptr i8, ptr %callee.frame, i64 8
  store i32 512, ptr %return.region.id.slot, align 4
  %3 = getelementptr i8, ptr %callee.frame, i64 24
  store i1 %fail2, ptr %3, align 8
  %fiber.resume.region.id5 = getelementptr inbounds nuw %fiber_control, ptr %fiber_control, i32 0, i32 5
  store i32 1024, ptr %fiber.resume.region.id5, align 4
  %fiber.fp6 = getelementptr inbounds nuw %fiber_control, ptr %fiber_control, i32 0, i32 4
  store i64 %callee.fp, ptr %fiber.fp6, align 8
  ret i32 0

outcome.i:                                        ; preds = %entry
  %fiber.outcome1 = getelementptr inbounds nuw %fiber_control, ptr %fiber_control, i32 0, i32 0
  %4 = call i32 @bpf_capsule_set_outcome(i32 %fiber, i64 -4294967291)
  br label %mixed_terminating_helper.exit.terminal

mixed_terminating_helper.exit.terminal:           ; preds = %outcome.i
  ret i32 1

root.prologue.overflow:                           ; preds = %root.prologue
  %fiber.outcome = getelementptr inbounds nuw %fiber_control, ptr %fiber_control, i32 0, i32 0
  %5 = call i32 @bpf_capsule_set_outcome(i32 %fiber, i64 -30064771069)
  ret i32 1

mixed_terminating_helper.exit.resume:             ; preds = %unit.test.left3
  %returned.frame = getelementptr i8, ptr %frame.addr, i64 -48
  %result.slot7 = getelementptr i8, ptr %returned.frame, i64 16
  %callret = load i32, ptr %result.slot7, align 8
  %first.reg2mem.slot = getelementptr i8, ptr %frame.addr, i64 -16
  store i32 %callret, ptr %first.reg2mem.slot, align 4
  %caller.sp8 = sub i64 %frame.fp, 16
  %callee.fp9 = sub i64 %caller.sp8, 32
  %callee.frame10 = getelementptr i8, ptr %frame.addr, i64 -48
  %saved.fp.slot11 = getelementptr i8, ptr %callee.frame10, i64 0
  store i64 %frame.fp, ptr %saved.fp.slot11, align 8
  %return.region.id.slot12 = getelementptr i8, ptr %callee.frame10, i64 8
  store i32 768, ptr %return.region.id.slot12, align 4
  %6 = getelementptr i8, ptr %callee.frame10, i64 24
  store i1 false, ptr %6, align 8
  %fiber.resume.region.id13 = getelementptr inbounds nuw %fiber_control, ptr %fiber_control, i32 0, i32 5
  store i32 1024, ptr %fiber.resume.region.id13, align 4
  %fiber.fp14 = getelementptr inbounds nuw %fiber_control, ptr %fiber_control, i32 0, i32 4
  store i64 %callee.fp9, ptr %fiber.fp14, align 8
  ret i32 0

mixed_terminating_helper.exit.resume.resume:      ; preds = %unit.test.right4
  %returned.frame15 = getelementptr i8, ptr %frame.addr, i64 -48
  %result.slot16 = getelementptr i8, ptr %returned.frame15, i64 16
  %callret17 = load i32, ptr %result.slot16, align 8
  %first.reg2mem.slot1 = getelementptr i8, ptr %frame.addr, i64 -16
  %first.reload = load i32, ptr %first.reg2mem.slot1, align 4
  %sum = add i32 %first.reload, %callret17
  %total = add i32 %sum, 11
  %result.slot = getelementptr i8, ptr %frame.addr, i64 16
  store i32 %total, ptr %result.slot, align 8
  %7 = getelementptr i8, ptr %frame.addr, i64 8
  %return.region.id = load i32, ptr %7, align 4
  %8 = getelementptr i8, ptr %frame.addr, i64 0
  %saved.fp = load i64, ptr %8, align 8
  %fiber.resume.region.id = getelementptr inbounds nuw %fiber_control, ptr %fiber_control, i32 0, i32 5
  store i32 %return.region.id, ptr %fiber.resume.region.id, align 4
  %return.sp = add i64 %frame.fp, 16
  %fiber.sp3 = getelementptr inbounds nuw %fiber_control, ptr %fiber_control, i32 0, i32 3
  store i64 %return.sp, ptr %fiber.sp3, align 8
  %fiber.fp4 = getelementptr inbounds nuw %fiber_control, ptr %fiber_control, i32 0, i32 4
  store i64 %saved.fp, ptr %fiber.fp4, align 8
  ret i32 0

unit.dispatch2:                                   ; preds = %unit.dispatch
  %9 = icmp ult i32 %region, 512
  br i1 %9, label %unit.test.left, label %unit.test.right

unit.test.left:                                   ; preds = %unit.dispatch2
  br label %root.prologue

unit.test.right:                                  ; preds = %unit.dispatch2
  %10 = icmp ult i32 %region, 768
  br i1 %10, label %unit.test.left3, label %unit.test.right4

unit.test.left3:                                  ; preds = %unit.test.right
  br label %mixed_terminating_helper.exit.resume

unit.test.right4:                                 ; preds = %unit.test.right
  br label %mixed_terminating_helper.exit.resume.resume
}

; Function Attrs: noinline
define i32 @bpf.unit.1(i32 %fiber, ptr "bpf.capsule.control" %fiber_control, i32 %region) #1 !bpf.capsule !2 !bpf.capsule.allocation.unit !3 !bpf.capsule.stack.size !0 !bpf.capsule.flatten.unit !4 {
unit.entry:
  %fiber.fp = getelementptr inbounds nuw %fiber_control, ptr %fiber_control, i32 0, i32 4
  %frame.fp = load i64, ptr %fiber.fp, align 8
  %frame.addr = inttoptr i64 %frame.fp to ptr
  call void asm sideeffect "# bpf_capsule_stack_anchor", "r"(ptr %fiber_control)
  br label %unit.dispatch

unit.dispatch:                                    ; preds = %unit.entry
  br label %unit.dispatch3

terminating_helper.prologue:                      ; preds = %unit.dispatch3
  %frame.sp = sub i64 %frame.fp, 0
  %slice.offset = and i64 %frame.fp, 262143
  %0 = icmp ult i64 %slice.offset, 131104
  br i1 %0, label %terminating_helper.prologue.overflow, label %entry

entry:                                            ; preds = %terminating_helper.prologue
  %fiber.sp = getelementptr inbounds nuw %fiber_control, ptr %fiber_control, i32 0, i32 3
  store i64 %frame.sp, ptr %fiber.sp, align 8
  %1 = getelementptr i8, ptr %frame.addr, i64 24
  %fail1 = load i1, ptr %1, align 1
  br i1 %fail1, label %outcome.route, label %return

return:                                           ; preds = %entry
  %result.slot = getelementptr i8, ptr %frame.addr, i64 16
  store i32 7, ptr %result.slot, align 8
  %2 = getelementptr i8, ptr %frame.addr, i64 8
  %return.region.id = load i32, ptr %2, align 4
  %3 = getelementptr i8, ptr %frame.addr, i64 0
  %saved.fp = load i64, ptr %3, align 8
  %fiber.resume.region.id = getelementptr inbounds nuw %fiber_control, ptr %fiber_control, i32 0, i32 5
  store i32 %return.region.id, ptr %fiber.resume.region.id, align 4
  %return.sp = add i64 %frame.fp, 16
  %fiber.sp2 = getelementptr inbounds nuw %fiber_control, ptr %fiber_control, i32 0, i32 3
  store i64 %return.sp, ptr %fiber.sp2, align 8
  %fiber.fp3 = getelementptr inbounds nuw %fiber_control, ptr %fiber_control, i32 0, i32 4
  store i64 %saved.fp, ptr %fiber.fp3, align 8
  ret i32 0

outcome.route:                                    ; preds = %entry
  %4 = getelementptr i8, ptr %frame.addr, i64 24
  %fail = load i1, ptr %4, align 1
  br i1 %fail, label %outcome.one, label %outcome.two

outcome.two:                                      ; preds = %outcome.route
  %fiber.outcome1 = getelementptr inbounds nuw %fiber_control, ptr %fiber_control, i32 0, i32 0
  %5 = call i32 @bpf_capsule_set_outcome(i32 %fiber, i64 -4294967292)
  br label %outcome.return

outcome.return:                                   ; preds = %outcome.one, %outcome.two
  ret i32 1

outcome.one:                                      ; preds = %outcome.route
  %fiber.outcome2 = getelementptr inbounds nuw %fiber_control, ptr %fiber_control, i32 0, i32 0
  %6 = call i32 @bpf_capsule_set_outcome(i32 %fiber, i64 -4294967293)
  br label %outcome.return

terminating_helper.prologue.overflow:             ; preds = %terminating_helper.prologue
  %fiber.outcome = getelementptr inbounds nuw %fiber_control, ptr %fiber_control, i32 0, i32 0
  %7 = call i32 @bpf_capsule_set_outcome(i32 %fiber, i64 -30064771069)
  ret i32 1

unit.dispatch3:                                   ; preds = %unit.dispatch
  br label %terminating_helper.prologue
}

; Function Attrs: noinline
define i32 @__bpf_capsule_trampoline_step(i32 %fiber, ptr "bpf.capsule.control" %fiber_control) #2 {
entry:
  %0 = icmp ne ptr %fiber_control, null
  br i1 %0, label %control.ready, label %control.missing

iterate:                                          ; preds = %control.ready
  %fiber.resume.region.id = getelementptr inbounds nuw %fiber_control, ptr %fiber_control, i32 0, i32 5
  %resume.region.id = load i32, ptr %fiber.resume.region.id, align 4
  %1 = icmp eq i32 %resume.region.id, -1
  %2 = icmp eq i32 %resume.region.id, 0
  %3 = or i1 %2, %1
  br i1 %3, label %terminal, label %route

control.ready:                                    ; preds = %entry
  br label %iterate

control.missing:                                  ; preds = %entry
  ret i32 1

route:                                            ; preds = %iterate
  br label %dispatch

dispatch:                                         ; preds = %route
  %step.index = and i32 %resume.region.id, 255
  %region.key = and i32 %resume.region.id, 16776960
  switch i32 %step.index, label %bad.id [
    i32 0, label %bpf.dispatch.output.scalar.0
  ]

bpf.dispatch.output.scalar.0:                     ; preds = %dispatch
  %4 = call i32 @bpf.dispatch.output.scalar.0(i32 %fiber, ptr %fiber_control, i32 %region.key)
  ret i32 %4

terminal:                                         ; preds = %iterate
  br i1 %1, label %completed, label %done

completed:                                        ; preds = %terminal
  store i32 0, ptr %fiber.resume.region.id, align 4
  br label %done

done:                                             ; preds = %completed, %terminal
  ret i32 1

bad.id:                                           ; preds = %dispatch
  %5 = call i32 @bpf_capsule_set_outcome(i32 %fiber, i64 -38654705661)
  ret i32 1
}

; Function Attrs: noinline
define i32 @bpf.dispatch.output.scalar.0(i32 %fiber, ptr "bpf.capsule.control" %fiber_control, i32 %region) #1 !bpf.capsule.flatten.root !4 {
entry:
  %0 = icmp ne ptr %fiber_control, null
  br i1 %0, label %dispatch, label %bad.id

dispatch:                                         ; preds = %entry
  br label %unit.route

unit.route:                                       ; preds = %dispatch
  %1 = icmp ult i32 %region, 1024
  br i1 %1, label %unit.route.left, label %unit.route.right

unit.route.left:                                  ; preds = %unit.route
  br label %bpf.unit.0

unit.route.right:                                 ; preds = %unit.route
  br label %bpf.unit.1

bad.id:                                           ; preds = %entry
  %2 = call i32 @bpf_capsule_set_outcome(i32 %fiber, i64 -38654705661)
  ret i32 1

bpf.unit.0:                                       ; preds = %unit.route.left
  %3 = call i32 @bpf.unit.0(i32 %fiber, ptr %fiber_control, i32 %region)
  ret i32 %3

bpf.unit.1:                                       ; preds = %unit.route.right
  %4 = call i32 @bpf.unit.1(i32 %fiber, ptr %fiber_control, i32 %region)
  ret i32 %4
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
