source_filename = "stackify-varargs.ll"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpfel"

%fiber_control = type { i32, i32, i64, i64, i64, i32, i32 }
%config = type { i32, i32, i32, i32, i32, i32, i32, i32, i32, i32, i32, i32, i64 }
%wide = type { i64, i64, i64 }

@bpf_capsule_fibers = global [1 x %fiber_control] zeroinitializer, section ".bss.bpfctrl", align 8
@bpf_capsule_config = constant %config { i32 0, i32 4096, i32 0, i32 0, i32 1, i32 4096, i32 1, i32 0, i32 1, i32 0, i32 1112556353, i32 5, i64 0 }, section ".rodata.bpfconfig", align 4
@sum_pointer = global ptr inttoptr (i64 4294967298 to ptr)
@wide_direct = global %wide { i64 4, i64 5, i64 6 }, align 8
@wide_indirect = global %wide { i64 10, i64 11, i64 12 }, align 8
@bpf_call_stack = internal global [262144 x i8] zeroinitializer, align 262144, !bpf.fiber.stack.size !0
@bpf_pc_unit = unnamed_addr constant [5 x i32] [i32 -1, i32 0, i32 1, i32 0, i32 0], section ".rodata.bpfpc", align 4

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

define i64 @start(i32 %fiber, ptr %pointer) section "syscall" !bpf.native !2 {
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
  store ptr %pointer, ptr %2, align 8
  %fiber.index3 = and i32 %fiber.index, 0
  %fiber.control4 = getelementptr inbounds [1 x %fiber_control], ptr @bpf_capsule_fibers, i32 0, i32 %fiber.index3, !bpf.capsule.sectioned.bounded !2
  %fiber.return.size = getelementptr inbounds nuw %fiber_control, ptr %fiber.control4, i32 0, i32 6
  store i32 8, ptr %fiber.return.size, align 4
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
  %root.result = load i64, ptr %fiber.stack13, align 8
  ret i64 %root.result
}

; Function Attrs: nocallback nofree nosync nounwind willreturn
declare void @llvm.va_start.p0(ptr) #1

; Function Attrs: nocallback nofree nosync nounwind willreturn
declare void @llvm.va_end.p0(ptr) #1

; Function Attrs: nocallback nofree nosync nounwind willreturn
declare void @llvm.va_copy.p0(ptr, ptr) #1

; Function Attrs: noinline
define i32 @bpf_capsule_set_outcome(i32 %fiber, i64 %outcome) #2 !bpf.native.scalar !2 {
entry:
  %fiber.index = and i32 %fiber, 0
  %fiber.control = getelementptr inbounds [1 x %fiber_control], ptr @bpf_capsule_fibers, i32 0, i32 %fiber.index, !bpf.capsule.sectioned.bounded !2
  %fiber.outcome = getelementptr inbounds nuw %fiber_control, ptr %fiber.control, i32 0, i32 0
  store volatile i64 %outcome, ptr %fiber.outcome, align 8
  ret i32 0
}

; Function Attrs: noinline
define i32 @bpf.unit.0(i32 %fiber, ptr "bpf.capsule.control" %fiber_control) #2 !bpf.capsule !2 !bpf.capsule.allocation.unit !3 !bpf.capsule.stack.size !0 !bpf.capsule.flatten.unit !3 {
unit.entry:
  %fiber.fp = getelementptr inbounds nuw %fiber_control, ptr %fiber_control, i32 0, i32 4
  %frame.fp = load i64, ptr %fiber.fp, align 8
  %frame.addr = inttoptr i64 %frame.fp to ptr
  %fiber.index = and i32 %fiber, 0
  %0 = zext i32 %fiber.index to i64
  %1 = mul i64 %0, 262144
  %stack.linear.offset = add i64 %1, 0
  %fiber.stack = getelementptr i8, ptr @bpf_call_stack, i64 %stack.linear.offset
  call void asm sideeffect "# bpf_capsule_stack_anchor", "r"(ptr %fiber.stack)
  %fiber.pc1 = getelementptr inbounds nuw %fiber_control, ptr %fiber_control, i32 0, i32 5
  %pc = load i32, ptr %fiber.pc1, align 4
  %2 = icmp ult i32 %pc, 3
  br i1 %2, label %unit.test.left, label %unit.test.right

root.prologue:                                    ; preds = %unit.test.left
  %frame.sp = sub i64 %frame.fp, 16
  %slice.offset = and i64 %frame.fp, 262143
  %3 = icmp ult i64 %slice.offset, 131200
  br i1 %3, label %root.prologue.overflow, label %entry

entry:                                            ; preds = %root.prologue
  %fiber.sp = getelementptr inbounds nuw %fiber_control, ptr %fiber_control, i32 0, i32 3
  store i64 %frame.sp, ptr %fiber.sp, align 8
  %4 = getelementptr i8, ptr %frame.addr, i64 24
  %pointer2 = load ptr, ptr %4, align 8
  %caller.sp = sub i64 %frame.fp, 16
  %callee.fp = sub i64 %caller.sp, 112
  %callee.frame = getelementptr i8, ptr %frame.addr, i64 -128
  %saved.fp.slot = getelementptr i8, ptr %callee.frame, i64 0
  store i64 %frame.fp, ptr %saved.fp.slot, align 8
  %return.pc.slot = getelementptr i8, ptr %callee.frame, i64 8
  store i32 3, ptr %return.pc.slot, align 4
  %5 = getelementptr i8, ptr %callee.frame, i64 24
  store i32 1, ptr %5, align 8
  %6 = getelementptr i8, ptr %callee.frame, i64 32
  store i32 2, ptr %6, align 8
  %7 = getelementptr i8, ptr %callee.frame, i64 48
  store i128 3, ptr %7, align 16
  %byval.copy = load %wide, ptr @wide_direct, align 8
  %byval.slot = getelementptr i8, ptr %callee.frame, i64 80
  store %wide %byval.copy, ptr %byval.slot, align 8
  %8 = getelementptr i8, ptr %callee.frame, i64 64
  store ptr %byval.slot, ptr %8, align 8
  %9 = getelementptr i8, ptr %callee.frame, i64 72
  store ptr %pointer2, ptr %9, align 8
  %fiber.pc5 = getelementptr inbounds nuw %fiber_control, ptr %fiber_control, i32 0, i32 5
  store i32 2, ptr %fiber.pc5, align 4
  %fiber.fp6 = getelementptr inbounds nuw %fiber_control, ptr %fiber_control, i32 0, i32 4
  store i64 %callee.fp, ptr %fiber.fp6, align 8
  ret i32 0

root.prologue.overflow:                           ; preds = %root.prologue
  %fiber.outcome = getelementptr inbounds nuw %fiber_control, ptr %fiber_control, i32 0, i32 0
  %10 = call i32 @bpf_capsule_set_outcome(i32 %fiber, i64 -30064771069)
  ret i32 0

entry.resume:                                     ; preds = %unit.test.left2
  %returned.frame = getelementptr i8, ptr %frame.addr, i64 -128
  %result.slot7 = getelementptr i8, ptr %returned.frame, i64 16
  %callret = load i64, ptr %result.slot7, align 8
  %direct.reg2mem.slot = getelementptr i8, ptr %frame.addr, i64 -16
  store i64 %callret, ptr %direct.reg2mem.slot, align 8
  %callee = load ptr, ptr @sum_pointer, align 8
  %11 = getelementptr i8, ptr %frame.addr, i64 24
  %pointer = load ptr, ptr %11, align 8
  %callee.token = ptrtoint ptr %callee to i64
  %callee.pc = trunc i64 %callee.token to i32
  %12 = sub i32 %callee.pc, 1
  %callee.pc.valid = icmp ult i32 %12, 2
  br i1 %callee.pc.valid, label %entry.resume.push, label %entry.resume.bad.callee

entry.resume.bad.callee:                          ; preds = %entry.resume
  %fiber.outcome8 = getelementptr inbounds nuw %fiber_control, ptr %fiber_control, i32 0, i32 0
  %13 = call i32 @bpf_capsule_set_outcome(i32 %fiber, i64 -38654705661)
  ret i32 0

entry.resume.push:                                ; preds = %entry.resume
  %caller.sp9 = sub i64 %frame.fp, 16
  %callee.fp10 = sub i64 %caller.sp9, 112
  %callee.frame11 = getelementptr i8, ptr %frame.addr, i64 -128
  %saved.fp.slot12 = getelementptr i8, ptr %callee.frame11, i64 0
  store i64 %frame.fp, ptr %saved.fp.slot12, align 8
  %return.pc.slot13 = getelementptr i8, ptr %callee.frame11, i64 8
  store i32 4, ptr %return.pc.slot13, align 4
  %14 = getelementptr i8, ptr %callee.frame11, i64 24
  store i32 7, ptr %14, align 8
  %15 = getelementptr i8, ptr %callee.frame11, i64 32
  store i32 8, ptr %15, align 8
  %16 = getelementptr i8, ptr %callee.frame11, i64 48
  store i128 9, ptr %16, align 16
  %byval.copy14 = load %wide, ptr @wide_indirect, align 8
  %byval.slot15 = getelementptr i8, ptr %callee.frame11, i64 80
  store %wide %byval.copy14, ptr %byval.slot15, align 8
  %17 = getelementptr i8, ptr %callee.frame11, i64 64
  store ptr %byval.slot15, ptr %17, align 8
  %18 = getelementptr i8, ptr %callee.frame11, i64 72
  store ptr %pointer, ptr %18, align 8
  %fiber.pc16 = getelementptr inbounds nuw %fiber_control, ptr %fiber_control, i32 0, i32 5
  store i32 %callee.pc, ptr %fiber.pc16, align 4
  %fiber.fp17 = getelementptr inbounds nuw %fiber_control, ptr %fiber_control, i32 0, i32 4
  store i64 %callee.fp10, ptr %fiber.fp17, align 8
  ret i32 0

entry.resume.resume:                              ; preds = %unit.test.right3
  %returned.frame18 = getelementptr i8, ptr %frame.addr, i64 -128
  %result.slot19 = getelementptr i8, ptr %returned.frame18, i64 16
  %callret20 = load i64, ptr %result.slot19, align 8
  %direct.reg2mem.slot1 = getelementptr i8, ptr %frame.addr, i64 -16
  %direct.reload = load i64, ptr %direct.reg2mem.slot1, align 8
  %result = add i64 %direct.reload, %callret20
  %result.slot = getelementptr i8, ptr %frame.addr, i64 16
  store i64 %result, ptr %result.slot, align 8
  %19 = getelementptr i8, ptr %frame.addr, i64 8
  %return.pc = load i32, ptr %19, align 4
  %20 = getelementptr i8, ptr %frame.addr, i64 0
  %saved.fp = load i64, ptr %20, align 8
  %fiber.pc = getelementptr inbounds nuw %fiber_control, ptr %fiber_control, i32 0, i32 5
  store i32 %return.pc, ptr %fiber.pc, align 4
  %return.sp = add i64 %frame.fp, 16
  %fiber.sp3 = getelementptr inbounds nuw %fiber_control, ptr %fiber_control, i32 0, i32 3
  store i64 %return.sp, ptr %fiber.sp3, align 8
  %fiber.fp4 = getelementptr inbounds nuw %fiber_control, ptr %fiber_control, i32 0, i32 4
  store i64 %saved.fp, ptr %fiber.fp4, align 8
  ret i32 0

unit.test.left:                                   ; preds = %unit.entry
  br label %root.prologue

unit.test.right:                                  ; preds = %unit.entry
  %21 = icmp ult i32 %pc, 4
  br i1 %21, label %unit.test.left2, label %unit.test.right3

unit.test.left2:                                  ; preds = %unit.test.right
  br label %entry.resume

unit.test.right3:                                 ; preds = %unit.test.right
  br label %entry.resume.resume
}

; Function Attrs: noinline
define i32 @bpf.unit.1(i32 %fiber, ptr "bpf.capsule.control" %fiber_control) #2 !bpf.capsule !2 !bpf.capsule.allocation.unit !3 !bpf.capsule.stack.size !0 !bpf.capsule.flatten.unit !3 {
unit.entry:
  %fiber.fp = getelementptr inbounds nuw %fiber_control, ptr %fiber_control, i32 0, i32 4
  %frame.fp = load i64, ptr %fiber.fp, align 8
  %frame.addr = inttoptr i64 %frame.fp to ptr
  %fiber.index = and i32 %fiber, 0
  %0 = zext i32 %fiber.index to i64
  %1 = mul i64 %0, 262144
  %stack.linear.offset = add i64 %1, 0
  %fiber.stack = getelementptr i8, ptr @bpf_call_stack, i64 %stack.linear.offset
  call void asm sideeffect "# bpf_capsule_stack_anchor", "r"(ptr %fiber.stack)
  %fiber.pc1 = getelementptr inbounds nuw %fiber_control, ptr %fiber_control, i32 0, i32 5
  %pc = load i32, ptr %fiber.pc1, align 4
  br label %sum_values.prologue

sum_values.prologue:                              ; preds = %unit.entry
  %frame.sp = sub i64 %frame.fp, 16
  %slice.offset = and i64 %frame.fp, 262143
  %2 = icmp ult i64 %slice.offset, 131200
  br i1 %2, label %sum_values.prologue.overflow, label %entry

entry:                                            ; preds = %sum_values.prologue
  %fiber.sp = getelementptr inbounds nuw %fiber_control, ptr %fiber_control, i32 0, i32 3
  store i64 %frame.sp, ptr %fiber.sp, align 8
  %list.slot3 = getelementptr i8, ptr %frame.addr, i64 -16
  %varargs.begin = getelementptr i8, ptr %frame.addr, i64 32
  store ptr %varargs.begin, ptr %list.slot3, align 8
  %list.slot2 = getelementptr i8, ptr %frame.addr, i64 -16
  %varargs.cursor = load ptr, ptr %list.slot2, align 8
  %3 = ptrtoint ptr %varargs.cursor to i64
  %4 = add i64 %3, 7
  %varargs.aligned = and i64 %4, -8
  %5 = inttoptr i64 %varargs.aligned to ptr
  %first8 = load i32, ptr %5, align 8
  %varargs.next = getelementptr i8, ptr %5, i64 8
  store ptr %varargs.next, ptr %list.slot2, align 8
  %list.slot1 = getelementptr i8, ptr %frame.addr, i64 -16
  %copy.slot7 = getelementptr i8, ptr %frame.addr, i64 -8
  %6 = load ptr, ptr %list.slot1, align 8
  store ptr %6, ptr %copy.slot7, align 8
  %copy.slot6 = getelementptr i8, ptr %frame.addr, i64 -8
  %varargs.cursor9 = load ptr, ptr %copy.slot6, align 8
  %7 = ptrtoint ptr %varargs.cursor9 to i64
  %8 = add i64 %7, 15
  %varargs.aligned10 = and i64 %8, -16
  %9 = inttoptr i64 %varargs.aligned10 to ptr
  %second11 = load i128, ptr %9, align 16
  %varargs.next12 = getelementptr i8, ptr %9, i64 16
  store ptr %varargs.next12, ptr %copy.slot6, align 8
  %copy.slot5 = getelementptr i8, ptr %frame.addr, i64 -8
  %varargs.cursor13 = load ptr, ptr %copy.slot5, align 8
  %10 = ptrtoint ptr %varargs.cursor13 to i64
  %11 = add i64 %10, 7
  %varargs.aligned14 = and i64 %11, -8
  %12 = inttoptr i64 %varargs.aligned14 to ptr
  %third.pointer15 = load ptr, ptr %12, align 8
  %varargs.next16 = getelementptr i8, ptr %12, i64 8
  store ptr %varargs.next16, ptr %copy.slot5, align 8
  %third = load %wide, ptr %third.pointer15, align 8
  %copy.slot4 = getelementptr i8, ptr %frame.addr, i64 -8
  %varargs.cursor17 = load ptr, ptr %copy.slot4, align 8
  %13 = ptrtoint ptr %varargs.cursor17 to i64
  %14 = add i64 %13, 7
  %varargs.aligned18 = and i64 %14, -8
  %15 = inttoptr i64 %varargs.aligned18 to ptr
  %fourth19 = load ptr, ptr %15, align 8
  %varargs.next20 = getelementptr i8, ptr %15, i64 8
  store ptr %varargs.next20, ptr %copy.slot4, align 8
  %copy.slot = getelementptr i8, ptr %frame.addr, i64 -8
  %list.slot = getelementptr i8, ptr %frame.addr, i64 -16
  %second.low = trunc i128 %second11 to i64
  %third.middle = extractvalue %wide %third, 1
  %fourth.bits = ptrtoint ptr %fourth19 to i64
  %first.wide = zext i32 %first8 to i64
  %16 = getelementptr i8, ptr %frame.addr, i64 24
  %fixed = load i32, ptr %16, align 4
  %fixed.wide = zext i32 %fixed to i64
  %a = add i64 %fixed.wide, %first.wide
  %b = add i64 %a, %second.low
  %c = add i64 %b, %third.middle
  %result = add i64 %c, %fourth.bits
  %result.slot = getelementptr i8, ptr %frame.addr, i64 16
  store i64 %result, ptr %result.slot, align 8
  %17 = getelementptr i8, ptr %frame.addr, i64 8
  %return.pc = load i32, ptr %17, align 4
  %18 = getelementptr i8, ptr %frame.addr, i64 0
  %saved.fp = load i64, ptr %18, align 8
  %fiber.pc = getelementptr inbounds nuw %fiber_control, ptr %fiber_control, i32 0, i32 5
  store i32 %return.pc, ptr %fiber.pc, align 4
  %return.sp = add i64 %frame.fp, 16
  %fiber.sp21 = getelementptr inbounds nuw %fiber_control, ptr %fiber_control, i32 0, i32 3
  store i64 %return.sp, ptr %fiber.sp21, align 8
  %fiber.fp22 = getelementptr inbounds nuw %fiber_control, ptr %fiber_control, i32 0, i32 4
  store i64 %saved.fp, ptr %fiber.fp22, align 8
  ret i32 0

sum_values.prologue.overflow:                     ; preds = %sum_values.prologue
  %fiber.outcome = getelementptr inbounds nuw %fiber_control, ptr %fiber_control, i32 0, i32 0
  %19 = call i32 @bpf_capsule_set_outcome(i32 %fiber, i64 -30064771069)
  ret i32 0
}

; Function Attrs: noinline
define i32 @__bpf_capsule_trampoline_step(i32 %fiber, ptr "bpf.capsule.control" %fiber_control) #3 !bpf.capsule.flatten.root !3 {
entry:
  %0 = icmp ne ptr %fiber_control, null
  br i1 %0, label %control.ready, label %control.missing

iterate:                                          ; preds = %control.ready
  %fiber.pc = getelementptr inbounds nuw %fiber_control, ptr %fiber_control, i32 0, i32 5
  %pc = load i32, ptr %fiber.pc, align 4
  %1 = icmp eq i32 %pc, -1
  %fiber.outcome = getelementptr inbounds nuw %fiber_control, ptr %fiber_control, i32 0, i32 0
  %2 = load i64, ptr %fiber.outcome, align 8
  %3 = icmp ne i64 %2, 0
  %4 = icmp eq i32 %pc, 0
  %5 = or i1 %1, %3
  %6 = or i1 %4, %5
  br i1 %6, label %terminal, label %route

control.ready:                                    ; preds = %entry
  br label %iterate

control.missing:                                  ; preds = %entry
  ret i32 1

route:                                            ; preds = %iterate
  br label %route.lookup

route.lookup:                                     ; preds = %route
  %7 = icmp ult i32 %pc, 5
  br i1 %7, label %route.pc.ready, label %bad.id

route.pc.ready:                                   ; preds = %route.lookup
  %8 = zext i32 %pc to i64
  %9 = getelementptr inbounds [5 x i32], ptr @bpf_pc_unit, i64 0, i64 %8
  %allocation.unit = load i32, ptr %9, align 4
  br label %dispatch

dispatch:                                         ; preds = %route.pc.ready
  switch i32 %allocation.unit, label %bad.id [
    i32 0, label %bpf.unit.0
    i32 1, label %bpf.unit.1
  ]

terminal:                                         ; preds = %iterate
  br i1 %1, label %completed, label %done

completed:                                        ; preds = %terminal
  store i32 0, ptr %fiber.pc, align 4
  br label %done

done:                                             ; preds = %completed, %terminal
  ret i32 1

bad.id:                                           ; preds = %dispatch, %route.lookup
  %10 = call i32 @bpf_capsule_set_outcome(i32 %fiber, i64 -38654705661)
  ret i32 1

bpf.unit.0:                                       ; preds = %dispatch
  %11 = call i32 @bpf.unit.0(i32 %fiber, ptr %fiber_control)
  ret i32 %11

bpf.unit.1:                                       ; preds = %dispatch
  %12 = call i32 @bpf.unit.1(i32 %fiber, ptr %fiber_control)
  ret i32 %12
}

attributes #0 = { "capsule.trampoline" }
attributes #1 = { nocallback nofree nosync nounwind willreturn }
attributes #2 = { noinline }
attributes #3 = { noinline "capsule.trampoline" }

!llvm.module.flags = !{!1}

!0 = !{i64 262144}
!1 = !{i32 1, !"bpf.capsule.classes", i32 1}
!2 = !{}
!3 = !{i32 0}
