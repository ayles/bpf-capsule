source_filename = "stackify-dynamic-alloca.ll"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpfel"

%fiber_control = type { i32, i32, i64, i64, i64, i32, i32 }
%config = type { i32, i32, i32, i32, i32, i32, i32, i32, i32, i32, i32, i32, i64 }

@bpf_capsule_fibers = global [1 x %fiber_control] zeroinitializer, section ".bss.bpfctrl", align 8
@bpf_capsule_config = constant %config { i32 0, i32 4096, i32 0, i32 0, i32 1, i32 4096, i32 1, i32 0, i32 1, i32 0, i32 1112556353, i32 5, i64 0 }, section ".rodata.bpfconfig", align 4
@bpf_call_stack = internal global [262144 x i8] zeroinitializer, align 262144, !bpf.fiber.stack.size !0
@bpf_pc_unit = unnamed_addr constant [5 x i32] [i32 -1, i32 1, i32 0, i32 0, i32 0], section ".rodata.bpfpc", align 4

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
  %stack.linear.offset = add i64 %1, 262080
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
  store i64 8, ptr %2, align 8
  %3 = getelementptr i8, ptr %fiber.stack, i64 32
  store i32 7, ptr %3, align 8
  %fiber.index3 = and i32 %fiber.index, 0
  %fiber.control4 = getelementptr inbounds [1 x %fiber_control], ptr @bpf_capsule_fibers, i32 0, i32 %fiber.index3, !bpf.capsule.sectioned.bounded !2
  %fiber.return.size = getelementptr inbounds nuw %fiber_control, ptr %fiber.control4, i32 0, i32 6
  store i32 4, ptr %fiber.return.size, align 4
  %fiber.index5 = and i32 %fiber.index, 0
  %fiber.control6 = getelementptr inbounds [1 x %fiber_control], ptr @bpf_capsule_fibers, i32 0, i32 %fiber.index5, !bpf.capsule.sectioned.bounded !2
  %fiber.pc = getelementptr inbounds nuw %fiber_control, ptr %fiber.control6, i32 0, i32 5
  store i32 2, ptr %fiber.pc, align 4
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
  %4 = zext i32 %fiber.index11 to i64
  %5 = mul i64 %4, 262144
  %stack.linear.offset12 = add i64 %5, 262096
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
define i32 @bpf.unit.0(i32 %fiber, ptr "bpf.capsule.control" %fiber_control) #1 !bpf.capsule !2 !bpf.capsule.allocation.unit !3 !bpf.capsule.stack.size !0 !bpf.capsule.flatten.unit !3 {
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
  %frame.sp = sub i64 %frame.fp, 32
  %slice.offset = and i64 %frame.fp, 262143
  %3 = icmp ult i64 %slice.offset, 131136
  br i1 %3, label %root.prologue.overflow, label %entry

entry:                                            ; preds = %root.prologue
  %fiber.sp = getelementptr inbounds nuw %fiber_control, ptr %fiber_control, i32 0, i32 3
  store i64 %frame.sp, ptr %fiber.sp, align 8
  %frame_alignment.slot = getelementptr i8, ptr %frame.addr, i64 -32
  store i8 9, ptr %frame_alignment.slot, align 32
  %fiber.sp1 = getelementptr inbounds nuw %fiber_control, ptr %fiber_control, i32 0, i32 3
  %frontier = load i64, ptr %fiber.sp1, align 8
  %4 = getelementptr i8, ptr %frame.addr, i64 24
  %count8 = load i64, ptr %4, align 8
  %5 = icmp ugt i64 %count8, 262144
  %6 = getelementptr i8, ptr %frame.addr, i64 24
  %count = load i64, ptr %6, align 8
  %carve.bytes = mul i64 %count, 1
  %carve.reserve = add i64 %carve.bytes, 31
  %slice.offset2 = and i64 %frontier, 262143
  %7 = add i64 %carve.reserve, 131104
  %8 = icmp ult i64 %slice.offset2, %7
  %carve.overflow = or i1 %5, %8
  br i1 %carve.overflow, label %entry.carve.abort, label %entry.carve

entry.carve:                                      ; preds = %entry
  %9 = sub i64 %frontier, %carve.bytes
  %frontier.next = and i64 %9, -32
  %fiber.sp4 = getelementptr inbounds nuw %fiber_control, ptr %fiber_control, i32 0, i32 3
  store i64 %frontier.next, ptr %fiber.sp4, align 8
  %frame.addr5 = inttoptr i64 %frontier.next to ptr
  %vla.handle = getelementptr i8, ptr %frame.addr, i64 -24
  store ptr %frame.addr5, ptr %vla.handle, align 8
  %10 = getelementptr i8, ptr %frame.addr, i64 -24
  %vla7 = load ptr, ptr %10, align 8
  store i8 5, ptr %vla7, align 1
  %11 = getelementptr i8, ptr %frame.addr, i64 32
  %value = load i32, ptr %11, align 4
  %fiber.sp11 = getelementptr inbounds nuw %fiber_control, ptr %fiber_control, i32 0, i32 3
  %caller.sp = load i64, ptr %fiber.sp11, align 8
  %callee.fp = sub i64 %caller.sp, 32
  %frame.addr12 = inttoptr i64 %callee.fp to ptr
  %saved.fp.slot = getelementptr i8, ptr %frame.addr12, i64 0
  store i64 %frame.fp, ptr %saved.fp.slot, align 8
  %return.pc.slot = getelementptr i8, ptr %frame.addr12, i64 8
  store i32 3, ptr %return.pc.slot, align 4
  %12 = getelementptr i8, ptr %frame.addr12, i64 24
  store i32 %value, ptr %12, align 8
  %fiber.pc13 = getelementptr inbounds nuw %fiber_control, ptr %fiber_control, i32 0, i32 5
  store i32 1, ptr %fiber.pc13, align 4
  %fiber.fp14 = getelementptr inbounds nuw %fiber_control, ptr %fiber_control, i32 0, i32 4
  store i64 %callee.fp, ptr %fiber.fp14, align 8
  ret i32 0

entry.carve.abort:                                ; preds = %entry
  %fiber.outcome3 = getelementptr inbounds nuw %fiber_control, ptr %fiber_control, i32 0, i32 0
  %13 = call i32 @bpf_capsule_set_outcome(i32 %fiber, i64 -30064771069)
  ret i32 0

root.prologue.overflow:                           ; preds = %root.prologue
  %fiber.outcome = getelementptr inbounds nuw %fiber_control, ptr %fiber_control, i32 0, i32 0
  %14 = call i32 @bpf_capsule_set_outcome(i32 %fiber, i64 -30064771069)
  ret i32 0

entry.carve.resume:                               ; preds = %unit.test.left2
  %fiber.sp15 = getelementptr inbounds nuw %fiber_control, ptr %fiber_control, i32 0, i32 3
  %return.sp16 = load i64, ptr %fiber.sp15, align 8
  %returned.fp = sub i64 %return.sp16, 16
  %frame.addr17 = inttoptr i64 %returned.fp to ptr
  %result.slot18 = getelementptr i8, ptr %frame.addr17, i64 16
  %callret = load i32, ptr %result.slot18, align 8
  %caller.sp.restored = add i64 %returned.fp, 32
  %fiber.sp19 = getelementptr inbounds nuw %fiber_control, ptr %fiber_control, i32 0, i32 3
  store i64 %caller.sp.restored, ptr %fiber.sp19, align 8
  %fiber.sp20 = getelementptr inbounds nuw %fiber_control, ptr %fiber_control, i32 0, i32 3
  %caller.sp21 = load i64, ptr %fiber.sp20, align 8
  %callee.fp22 = sub i64 %caller.sp21, 32
  %frame.addr23 = inttoptr i64 %callee.fp22 to ptr
  %saved.fp.slot24 = getelementptr i8, ptr %frame.addr23, i64 0
  store i64 %frame.fp, ptr %saved.fp.slot24, align 8
  %return.pc.slot25 = getelementptr i8, ptr %frame.addr23, i64 8
  store i32 4, ptr %return.pc.slot25, align 4
  %15 = getelementptr i8, ptr %frame.addr23, i64 24
  store i32 %callret, ptr %15, align 8
  %fiber.pc26 = getelementptr inbounds nuw %fiber_control, ptr %fiber_control, i32 0, i32 5
  store i32 1, ptr %fiber.pc26, align 4
  %fiber.fp27 = getelementptr inbounds nuw %fiber_control, ptr %fiber_control, i32 0, i32 4
  store i64 %callee.fp22, ptr %fiber.fp27, align 8
  ret i32 0

entry.carve.resume.resume:                        ; preds = %unit.test.right3
  %fiber.sp28 = getelementptr inbounds nuw %fiber_control, ptr %fiber_control, i32 0, i32 3
  %return.sp29 = load i64, ptr %fiber.sp28, align 8
  %returned.fp30 = sub i64 %return.sp29, 16
  %frame.addr31 = inttoptr i64 %returned.fp30 to ptr
  %result.slot32 = getelementptr i8, ptr %frame.addr31, i64 16
  %callret33 = load i32, ptr %result.slot32, align 8
  %caller.sp.restored34 = add i64 %returned.fp30, 32
  %fiber.sp35 = getelementptr inbounds nuw %fiber_control, ptr %fiber_control, i32 0, i32 3
  store i64 %caller.sp.restored34, ptr %fiber.sp35, align 8
  %16 = getelementptr i8, ptr %frame.addr, i64 -24
  %vla6 = load ptr, ptr %16, align 8
  %byte = load i8, ptr %vla6, align 1
  %extended = zext i8 %byte to i32
  %result = add i32 %callret33, %extended
  %result.slot = getelementptr i8, ptr %frame.addr, i64 16
  store i32 %result, ptr %result.slot, align 8
  %17 = getelementptr i8, ptr %frame.addr, i64 8
  %return.pc = load i32, ptr %17, align 4
  %18 = getelementptr i8, ptr %frame.addr, i64 0
  %saved.fp = load i64, ptr %18, align 8
  %fiber.pc = getelementptr inbounds nuw %fiber_control, ptr %fiber_control, i32 0, i32 5
  store i32 %return.pc, ptr %fiber.pc, align 4
  %return.sp = add i64 %frame.fp, 16
  %fiber.sp9 = getelementptr inbounds nuw %fiber_control, ptr %fiber_control, i32 0, i32 3
  store i64 %return.sp, ptr %fiber.sp9, align 8
  %fiber.fp10 = getelementptr inbounds nuw %fiber_control, ptr %fiber_control, i32 0, i32 4
  store i64 %saved.fp, ptr %fiber.fp10, align 8
  ret i32 0

unit.test.left:                                   ; preds = %unit.entry
  br label %root.prologue

unit.test.right:                                  ; preds = %unit.entry
  %19 = icmp ult i32 %pc, 4
  br i1 %19, label %unit.test.left2, label %unit.test.right3

unit.test.left2:                                  ; preds = %unit.test.right
  br label %entry.carve.resume

unit.test.right3:                                 ; preds = %unit.test.right
  br label %entry.carve.resume.resume
}

; Function Attrs: noinline
define i32 @bpf.unit.1(i32 %fiber, ptr "bpf.capsule.control" %fiber_control) #1 !bpf.capsule !2 !bpf.capsule.allocation.unit !3 !bpf.capsule.stack.size !0 !bpf.capsule.flatten.unit !3 {
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
  br label %ordinary_helper.prologue

ordinary_helper.prologue:                         ; preds = %unit.entry
  %frame.sp = sub i64 %frame.fp, 0
  %slice.offset = and i64 %frame.fp, 262143
  %2 = icmp ult i64 %slice.offset, 131104
  br i1 %2, label %ordinary_helper.prologue.overflow, label %entry

entry:                                            ; preds = %ordinary_helper.prologue
  %fiber.sp = getelementptr inbounds nuw %fiber_control, ptr %fiber_control, i32 0, i32 3
  store i64 %frame.sp, ptr %fiber.sp, align 8
  %3 = getelementptr i8, ptr %frame.addr, i64 24
  %value = load i32, ptr %3, align 4
  %result = add i32 %value, 1
  %result.slot = getelementptr i8, ptr %frame.addr, i64 16
  store i32 %result, ptr %result.slot, align 8
  %4 = getelementptr i8, ptr %frame.addr, i64 8
  %return.pc = load i32, ptr %4, align 4
  %5 = getelementptr i8, ptr %frame.addr, i64 0
  %saved.fp = load i64, ptr %5, align 8
  %fiber.pc = getelementptr inbounds nuw %fiber_control, ptr %fiber_control, i32 0, i32 5
  store i32 %return.pc, ptr %fiber.pc, align 4
  %return.sp = add i64 %frame.fp, 16
  %fiber.sp1 = getelementptr inbounds nuw %fiber_control, ptr %fiber_control, i32 0, i32 3
  store i64 %return.sp, ptr %fiber.sp1, align 8
  %fiber.fp2 = getelementptr inbounds nuw %fiber_control, ptr %fiber_control, i32 0, i32 4
  store i64 %saved.fp, ptr %fiber.fp2, align 8
  ret i32 0

ordinary_helper.prologue.overflow:                ; preds = %ordinary_helper.prologue
  %fiber.outcome = getelementptr inbounds nuw %fiber_control, ptr %fiber_control, i32 0, i32 0
  %6 = call i32 @bpf_capsule_set_outcome(i32 %fiber, i64 -30064771069)
  ret i32 0
}

; Function Attrs: noinline
define i32 @__bpf_capsule_trampoline_step(i32 %fiber, ptr "bpf.capsule.control" %fiber_control) #2 !bpf.capsule.flatten.root !3 {
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
attributes #1 = { noinline }
attributes #2 = { noinline "capsule.trampoline" }

!llvm.module.flags = !{!1}

!0 = !{i64 262144}
!1 = !{i32 1, !"bpf.capsule.classes", i32 1}
!2 = !{}
!3 = !{i32 0}
