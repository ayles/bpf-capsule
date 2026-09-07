source_filename = "stackify-borrowed-context.ll"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpfel"

%fiber_control = type { i32, i32, i64, i64, i64, i32, i32 }
%config = type { i32, i32, i32, i32, i32, i32, i32, i32, i32, i32, i32, i32, i64 }

@bpf_capsule_fibers = global [1 x %fiber_control] zeroinitializer, section ".bss.bpfctrl", align 8
@bpf_capsule_config = constant %config { i32 0, i32 4096, i32 0, i32 0, i32 1, i32 4096, i32 1, i32 0, i32 1, i32 0, i32 1112556353, i32 8, i64 0 }, section ".rodata.bpfconfig", align 4
@bpf_call_stack = internal global [262144 x i8] zeroinitializer, align 262144, !bpf.fiber.stack.size !0

define i32 @__bpf_capsule_trampoline_l1(i32 %fiber, ptr %control) #0 !dbg !6 {
entry:
  %status = call i32 @__bpf_capsule_trampoline_step(i32 %fiber, ptr %control), !dbg !19
  ret i32 %status, !dbg !19
}

define i32 @__bpf_capsule_trampoline(i32 %fiber) #0 {
entry:
  %control = getelementptr [1 x %fiber_control], ptr @bpf_capsule_fibers, i32 0, i32 %fiber
  %status = call i32 @__bpf_capsule_trampoline_l1(i32 %fiber, ptr %control)
  ret i32 %status
}

define i32 @__bpf_capsule_trampoline_ctx_l1(ptr %context, i32 %fiber, ptr %control) #0 !dbg !20 {
entry:
  %status = call i32 @__bpf_capsule_trampoline_ctx_step(ptr %context, i32 %fiber, ptr %control), !dbg !29
  ret i32 %status, !dbg !29
}

define i32 @__bpf_capsule_trampoline_ctx(ptr %context, i32 %fiber) #0 {
entry:
  %control = getelementptr [1 x %fiber_control], ptr @bpf_capsule_fibers, i32 0, i32 %fiber
  %status = call i32 @__bpf_capsule_trampoline_ctx_l1(ptr %context, i32 %fiber, ptr %control)
  ret i32 %status
}

define i32 @start(ptr %context, i32 %fiber) section "xdp" !dbg !30 !bpf.native !33 {
entry:
  %fiber.index = and i32 %fiber, 0
  %fiber.index1 = and i32 %fiber.index, 0
  %0 = zext i32 %fiber.index1 to i64
  %1 = mul i64 %0, 262144
  %stack.linear.offset = add i64 %1, 262112
  %fiber.stack = getelementptr i8, ptr @bpf_call_stack, i64 %stack.linear.offset
  %root.fp = ptrtoint ptr %fiber.stack to i64
  %fiber.index2 = and i32 %fiber.index, 0
  %fiber.control = getelementptr inbounds [1 x %fiber_control], ptr @bpf_capsule_fibers, i32 0, i32 %fiber.index2, !bpf.capsule.sectioned.bounded !33
  %fiber.outcome = getelementptr inbounds nuw %fiber_control, ptr %fiber.control, i32 0, i32 0
  store i64 0, ptr %fiber.outcome, align 8
  %root.saved.fp = getelementptr i8, ptr %fiber.stack, i64 0
  store i64 0, ptr %root.saved.fp, align 8
  %root.return.region.id = getelementptr i8, ptr %fiber.stack, i64 8
  store i32 -1, ptr %root.return.region.id, align 4
  %fiber.index3 = and i32 %fiber.index, 0
  %fiber.control4 = getelementptr inbounds [1 x %fiber_control], ptr @bpf_capsule_fibers, i32 0, i32 %fiber.index3, !bpf.capsule.sectioned.bounded !33
  %fiber.return.size = getelementptr inbounds nuw %fiber_control, ptr %fiber.control4, i32 0, i32 6
  store i32 4, ptr %fiber.return.size, align 4
  %fiber.index5 = and i32 %fiber.index, 0
  %fiber.control6 = getelementptr inbounds [1 x %fiber_control], ptr @bpf_capsule_fibers, i32 0, i32 %fiber.index5, !bpf.capsule.sectioned.bounded !33
  %fiber.resume.region.id = getelementptr inbounds nuw %fiber_control, ptr %fiber.control6, i32 0, i32 5
  store i32 256, ptr %fiber.resume.region.id, align 4
  %fiber.index7 = and i32 %fiber.index, 0
  %fiber.control8 = getelementptr inbounds [1 x %fiber_control], ptr @bpf_capsule_fibers, i32 0, i32 %fiber.index7, !bpf.capsule.sectioned.bounded !33
  %fiber.sp = getelementptr inbounds nuw %fiber_control, ptr %fiber.control8, i32 0, i32 3
  store i64 %root.fp, ptr %fiber.sp, align 8
  %fiber.index9 = and i32 %fiber.index, 0
  %fiber.control10 = getelementptr inbounds [1 x %fiber_control], ptr @bpf_capsule_fibers, i32 0, i32 %fiber.index9, !bpf.capsule.sectioned.bounded !33
  %fiber.fp = getelementptr inbounds nuw %fiber_control, ptr %fiber.control10, i32 0, i32 4
  store i64 %root.fp, ptr %fiber.fp, align 8
  %control.i = getelementptr [1 x %fiber_control], ptr @bpf_capsule_fibers, i32 0, i32 %fiber.index
  %status.i = call i32 @__bpf_capsule_trampoline_ctx_l1(ptr %context, i32 %fiber.index, ptr %control.i), !dbg !34
  %fiber.index11 = and i32 %fiber.index, 0
  %2 = zext i32 %fiber.index11 to i64
  %3 = mul i64 %2, 262144
  %stack.linear.offset12 = add i64 %3, 262128
  %fiber.stack13 = getelementptr i8, ptr @bpf_call_stack, i64 %stack.linear.offset12
  %root.result = load i32, ptr %fiber.stack13, align 8
  ret i32 %root.result
}

define i32 @start_scalar(i32 %fiber) section "syscall" !bpf.native !33 {
entry:
  %fiber.index = and i32 %fiber, 0
  %fiber.index1 = and i32 %fiber.index, 0
  %0 = zext i32 %fiber.index1 to i64
  %1 = mul i64 %0, 262144
  %stack.linear.offset = add i64 %1, 262112
  %fiber.stack = getelementptr i8, ptr @bpf_call_stack, i64 %stack.linear.offset
  %root.fp = ptrtoint ptr %fiber.stack to i64
  %fiber.index2 = and i32 %fiber.index, 0
  %fiber.control = getelementptr inbounds [1 x %fiber_control], ptr @bpf_capsule_fibers, i32 0, i32 %fiber.index2, !bpf.capsule.sectioned.bounded !33
  %fiber.outcome = getelementptr inbounds nuw %fiber_control, ptr %fiber.control, i32 0, i32 0
  store i64 0, ptr %fiber.outcome, align 8
  %root.saved.fp = getelementptr i8, ptr %fiber.stack, i64 0
  store i64 0, ptr %root.saved.fp, align 8
  %root.return.region.id = getelementptr i8, ptr %fiber.stack, i64 8
  store i32 -1, ptr %root.return.region.id, align 4
  %2 = getelementptr i8, ptr %fiber.stack, i64 24
  store i32 5, ptr %2, align 8
  %fiber.index3 = and i32 %fiber.index, 0
  %fiber.control4 = getelementptr inbounds [1 x %fiber_control], ptr @bpf_capsule_fibers, i32 0, i32 %fiber.index3, !bpf.capsule.sectioned.bounded !33
  %fiber.return.size = getelementptr inbounds nuw %fiber_control, ptr %fiber.control4, i32 0, i32 6
  store i32 4, ptr %fiber.return.size, align 4
  %fiber.index5 = and i32 %fiber.index, 0
  %fiber.control6 = getelementptr inbounds [1 x %fiber_control], ptr @bpf_capsule_fibers, i32 0, i32 %fiber.index5, !bpf.capsule.sectioned.bounded !33
  %fiber.resume.region.id = getelementptr inbounds nuw %fiber_control, ptr %fiber.control6, i32 0, i32 5
  store i32 1536, ptr %fiber.resume.region.id, align 4
  %fiber.index7 = and i32 %fiber.index, 0
  %fiber.control8 = getelementptr inbounds [1 x %fiber_control], ptr @bpf_capsule_fibers, i32 0, i32 %fiber.index7, !bpf.capsule.sectioned.bounded !33
  %fiber.sp = getelementptr inbounds nuw %fiber_control, ptr %fiber.control8, i32 0, i32 3
  store i64 %root.fp, ptr %fiber.sp, align 8
  %fiber.index9 = and i32 %fiber.index, 0
  %fiber.control10 = getelementptr inbounds [1 x %fiber_control], ptr @bpf_capsule_fibers, i32 0, i32 %fiber.index9, !bpf.capsule.sectioned.bounded !33
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
define i32 @bpf_capsule_set_outcome(i32 %fiber, i64 %outcome) #1 !dbg !35 !bpf.native.scalar !33 {
entry:
  %fiber.index = and i32 %fiber, 0, !dbg !42
  %fiber.control = getelementptr inbounds [1 x %fiber_control], ptr @bpf_capsule_fibers, i32 0, i32 %fiber.index, !dbg !42, !bpf.capsule.sectioned.bounded !33
  %fiber.outcome = getelementptr inbounds nuw %fiber_control, ptr %fiber.control, i32 0, i32 0, !dbg !42
  store volatile i64 %outcome, ptr %fiber.outcome, align 8, !dbg !42
  ret i32 0, !dbg !42
}

; Function Attrs: noinline
define i32 @bpf.unit.0(i32 %fiber, ptr "bpf.capsule.control" %fiber_control, i32 %region) #1 !dbg !43 !bpf.capsule !33 !bpf.capsule.allocation.unit !50 !bpf.capsule.stack.size !0 !bpf.capsule.flatten.unit !51 {
unit.entry:
  %fiber.fp = getelementptr inbounds nuw %fiber_control, ptr %fiber_control, i32 0, i32 4
  %frame.fp = load i64, ptr %fiber.fp, align 8
  %frame.addr = inttoptr i64 %frame.fp to ptr
  call void asm sideeffect "# bpf_capsule_stack_anchor", "r"(ptr %fiber_control), !dbg !52
  br label %unit.dispatch

unit.dispatch:                                    ; preds = %unit.entry
  br label %unit.dispatch1

borrowed_root.prologue:                           ; preds = %unit.test.left2
  %frame.sp = sub i64 %frame.fp, 0
  %slice.offset = and i64 %frame.fp, 262143
  %0 = icmp ult i64 %slice.offset, 131104
  br i1 %0, label %borrowed_root.prologue.overflow, label %entry

entry:                                            ; preds = %borrowed_root.prologue
  %fiber.sp = getelementptr inbounds nuw %fiber_control, ptr %fiber_control, i32 0, i32 3
  store i64 %frame.sp, ptr %fiber.sp, align 8
  %caller.sp = sub i64 %frame.fp, 0
  %callee.fp = sub i64 %caller.sp, 32
  %callee.frame = getelementptr i8, ptr %frame.addr, i64 -32
  %saved.fp.slot = getelementptr i8, ptr %callee.frame, i64 0
  store i64 %frame.fp, ptr %saved.fp.slot, align 8
  %return.region.id.slot = getelementptr i8, ptr %callee.frame, i64 8
  store i32 512, ptr %return.region.id.slot, align 4
  %1 = getelementptr i8, ptr %callee.frame, i64 24
  store i32 5, ptr %1, align 8
  %fiber.resume.region.id3 = getelementptr inbounds nuw %fiber_control, ptr %fiber_control, i32 0, i32 5
  store i32 257, ptr %fiber.resume.region.id3, align 4
  %fiber.fp4 = getelementptr inbounds nuw %fiber_control, ptr %fiber_control, i32 0, i32 4
  store i64 %callee.fp, ptr %fiber.fp4, align 8
  ret i32 0

borrowed_root.prologue.overflow:                  ; preds = %borrowed_root.prologue
  %fiber.outcome = getelementptr inbounds nuw %fiber_control, ptr %fiber_control, i32 0, i32 0
  %2 = call i32 @bpf_capsule_set_outcome(i32 %fiber, i64 -30064771069), !dbg !52
  ret i32 1

entry.resume:                                     ; preds = %unit.test.right3
  %returned.frame = getelementptr i8, ptr %frame.addr, i64 -32
  %result.slot5 = getelementptr i8, ptr %returned.frame, i64 16
  %callret = load i32, ptr %result.slot5, align 8
  %caller.sp6 = sub i64 %frame.fp, 0
  %callee.fp7 = sub i64 %caller.sp6, 32
  %callee.frame8 = getelementptr i8, ptr %frame.addr, i64 -32
  %saved.fp.slot9 = getelementptr i8, ptr %callee.frame8, i64 0
  store i64 %frame.fp, ptr %saved.fp.slot9, align 8
  %return.region.id.slot10 = getelementptr i8, ptr %callee.frame8, i64 8
  store i32 768, ptr %return.region.id.slot10, align 4
  %3 = getelementptr i8, ptr %callee.frame8, i64 24
  store i32 %callret, ptr %3, align 8
  %fiber.resume.region.id11 = getelementptr inbounds nuw %fiber_control, ptr %fiber_control, i32 0, i32 5
  store i32 1536, ptr %fiber.resume.region.id11, align 4
  %fiber.fp12 = getelementptr inbounds nuw %fiber_control, ptr %fiber_control, i32 0, i32 4
  store i64 %callee.fp7, ptr %fiber.fp12, align 8
  ret i32 0

entry.resume.resume:                              ; preds = %unit.test.left4
  %returned.frame13 = getelementptr i8, ptr %frame.addr, i64 -32
  %result.slot14 = getelementptr i8, ptr %returned.frame13, i64 16
  %callret15 = load i32, ptr %result.slot14, align 8
  %caller.sp16 = sub i64 %frame.fp, 0
  %callee.fp17 = sub i64 %caller.sp16, 32
  %callee.frame18 = getelementptr i8, ptr %frame.addr, i64 -32
  %saved.fp.slot19 = getelementptr i8, ptr %callee.frame18, i64 0
  store i64 %frame.fp, ptr %saved.fp.slot19, align 8
  %return.region.id.slot20 = getelementptr i8, ptr %callee.frame18, i64 8
  store i32 1024, ptr %return.region.id.slot20, align 4
  %4 = getelementptr i8, ptr %callee.frame18, i64 24
  store i32 %callret15, ptr %4, align 8
  %fiber.resume.region.id21 = getelementptr inbounds nuw %fiber_control, ptr %fiber_control, i32 0, i32 5
  store i32 257, ptr %fiber.resume.region.id21, align 4
  %fiber.fp22 = getelementptr inbounds nuw %fiber_control, ptr %fiber_control, i32 0, i32 4
  store i64 %callee.fp17, ptr %fiber.fp22, align 8
  ret i32 0

entry.resume.resume.resume:                       ; preds = %unit.test.left6
  %returned.frame23 = getelementptr i8, ptr %frame.addr, i64 -32
  %result.slot24 = getelementptr i8, ptr %returned.frame23, i64 16
  %callret25 = load i32, ptr %result.slot24, align 8
  %caller.sp26 = sub i64 %frame.fp, 0
  %callee.fp27 = sub i64 %caller.sp26, 32
  %callee.frame28 = getelementptr i8, ptr %frame.addr, i64 -32
  %saved.fp.slot29 = getelementptr i8, ptr %callee.frame28, i64 0
  store i64 %frame.fp, ptr %saved.fp.slot29, align 8
  %return.region.id.slot30 = getelementptr i8, ptr %callee.frame28, i64 8
  store i32 1280, ptr %return.region.id.slot30, align 4
  %5 = getelementptr i8, ptr %callee.frame28, i64 24
  store i32 %callret25, ptr %5, align 8
  %fiber.resume.region.id31 = getelementptr inbounds nuw %fiber_control, ptr %fiber_control, i32 0, i32 5
  store i32 1536, ptr %fiber.resume.region.id31, align 4
  %fiber.fp32 = getelementptr inbounds nuw %fiber_control, ptr %fiber_control, i32 0, i32 4
  store i64 %callee.fp27, ptr %fiber.fp32, align 8
  ret i32 0

entry.resume.resume.resume.resume:                ; preds = %unit.test.right7
  %returned.frame33 = getelementptr i8, ptr %frame.addr, i64 -32
  %result.slot34 = getelementptr i8, ptr %returned.frame33, i64 16
  %callret35 = load i32, ptr %result.slot34, align 8
  %result.slot = getelementptr i8, ptr %frame.addr, i64 16
  store i32 %callret35, ptr %result.slot, align 8
  %6 = getelementptr i8, ptr %frame.addr, i64 8
  %return.region.id = load i32, ptr %6, align 4
  %7 = getelementptr i8, ptr %frame.addr, i64 0
  %saved.fp = load i64, ptr %7, align 8
  %fiber.resume.region.id = getelementptr inbounds nuw %fiber_control, ptr %fiber_control, i32 0, i32 5
  store i32 %return.region.id, ptr %fiber.resume.region.id, align 4
  %return.sp = add i64 %frame.fp, 16
  %fiber.sp1 = getelementptr inbounds nuw %fiber_control, ptr %fiber_control, i32 0, i32 3
  store i64 %return.sp, ptr %fiber.sp1, align 8
  %fiber.fp2 = getelementptr inbounds nuw %fiber_control, ptr %fiber_control, i32 0, i32 4
  store i64 %saved.fp, ptr %fiber.fp2, align 8
  ret i32 0

unit.dispatch1:                                   ; preds = %unit.dispatch
  %8 = icmp ult i32 %region, 3, !dbg !52
  br i1 %8, label %unit.test.left, label %unit.test.right, !dbg !52

unit.test.left:                                   ; preds = %unit.dispatch1
  %9 = icmp ult i32 %region, 2
  br i1 %9, label %unit.test.left2, label %unit.test.right3

unit.test.right:                                  ; preds = %unit.dispatch1
  %10 = icmp ult i32 %region, 4
  br i1 %10, label %unit.test.left4, label %unit.test.right5

unit.test.left2:                                  ; preds = %unit.test.left
  br label %borrowed_root.prologue

unit.test.right3:                                 ; preds = %unit.test.left
  br label %entry.resume

unit.test.left4:                                  ; preds = %unit.test.right
  br label %entry.resume.resume

unit.test.right5:                                 ; preds = %unit.test.right
  %11 = icmp ult i32 %region, 5
  br i1 %11, label %unit.test.left6, label %unit.test.right7

unit.test.left6:                                  ; preds = %unit.test.right5
  br label %entry.resume.resume.resume

unit.test.right7:                                 ; preds = %unit.test.right5
  br label %entry.resume.resume.resume.resume
}

; Function Attrs: noinline
define i32 @bpf.unit.1(i32 %fiber, ptr "bpf.capsule.control" %fiber_control, i32 %region) #1 !dbg !53 !bpf.capsule !33 !bpf.capsule.allocation.unit !50 !bpf.capsule.stack.size !0 !bpf.capsule.flatten.unit !51 {
unit.entry:
  %fiber.fp = getelementptr inbounds nuw %fiber_control, ptr %fiber_control, i32 0, i32 4
  %frame.fp = load i64, ptr %fiber.fp, align 8
  %frame.addr = inttoptr i64 %frame.fp to ptr
  call void asm sideeffect "# bpf_capsule_stack_anchor", "r"(ptr %fiber_control), !dbg !58
  br label %unit.dispatch

unit.dispatch:                                    ; preds = %unit.entry
  br label %unit.dispatch1

scalar_helper.prologue:                           ; preds = %unit.dispatch1
  %frame.sp = sub i64 %frame.fp, 0
  %slice.offset = and i64 %frame.fp, 262143
  %0 = icmp ult i64 %slice.offset, 131104
  br i1 %0, label %scalar_helper.prologue.overflow, label %entry

entry:                                            ; preds = %scalar_helper.prologue
  %fiber.sp = getelementptr inbounds nuw %fiber_control, ptr %fiber_control, i32 0, i32 3
  store i64 %frame.sp, ptr %fiber.sp, align 8
  %1 = getelementptr i8, ptr %frame.addr, i64 24
  %value = load i32, ptr %1, align 4
  %result = add i32 %value, 1
  %result.slot = getelementptr i8, ptr %frame.addr, i64 16
  store i32 %result, ptr %result.slot, align 8
  %2 = getelementptr i8, ptr %frame.addr, i64 8
  %return.region.id = load i32, ptr %2, align 4
  %3 = getelementptr i8, ptr %frame.addr, i64 0
  %saved.fp = load i64, ptr %3, align 8
  %fiber.resume.region.id = getelementptr inbounds nuw %fiber_control, ptr %fiber_control, i32 0, i32 5
  store i32 %return.region.id, ptr %fiber.resume.region.id, align 4
  %return.sp = add i64 %frame.fp, 16
  %fiber.sp1 = getelementptr inbounds nuw %fiber_control, ptr %fiber_control, i32 0, i32 3
  store i64 %return.sp, ptr %fiber.sp1, align 8
  %fiber.fp2 = getelementptr inbounds nuw %fiber_control, ptr %fiber_control, i32 0, i32 4
  store i64 %saved.fp, ptr %fiber.fp2, align 8
  ret i32 0

scalar_helper.prologue.overflow:                  ; preds = %scalar_helper.prologue
  %fiber.outcome = getelementptr inbounds nuw %fiber_control, ptr %fiber_control, i32 0, i32 0
  %4 = call i32 @bpf_capsule_set_outcome(i32 %fiber, i64 -30064771069), !dbg !58
  ret i32 1

unit.dispatch1:                                   ; preds = %unit.dispatch
  br label %scalar_helper.prologue, !dbg !58
}

; Function Attrs: noinline
define i32 @bpf.unit.2(ptr "bpf.capsule.borrowed" %ctx, i32 %fiber, ptr "bpf.capsule.control" %fiber_control, i32 %region) #1 !dbg !59 !bpf.capsule !33 !bpf.capsule.allocation.unit !67 !bpf.capsule.stack.size !0 !bpf.capsule.flatten.unit !68 {
unit.entry:
  %fiber.fp = getelementptr inbounds nuw %fiber_control, ptr %fiber_control, i32 0, i32 4
  %frame.fp = load i64, ptr %fiber.fp, align 8
  %frame.addr = inttoptr i64 %frame.fp to ptr
  call void asm sideeffect "# bpf_capsule_stack_anchor", "r"(ptr %fiber_control), !dbg !69
  br label %unit.dispatch

unit.dispatch:                                    ; preds = %unit.entry
  br label %unit.dispatch1

context_helper.prologue:                          ; preds = %unit.dispatch1
  %frame.sp = sub i64 %frame.fp, 0
  %slice.offset = and i64 %frame.fp, 262143
  %0 = icmp ult i64 %slice.offset, 131104
  br i1 %0, label %context_helper.prologue.overflow, label %entry

entry:                                            ; preds = %context_helper.prologue
  %fiber.sp = getelementptr inbounds nuw %fiber_control, ptr %fiber_control, i32 0, i32 3
  store i64 %frame.sp, ptr %fiber.sp, align 8
  call void asm sideeffect "", "r"(ptr %ctx), !dbg !69
  %1 = getelementptr i8, ptr %frame.addr, i64 24
  %value = load i32, ptr %1, align 4
  %result = add i32 %value, 1
  %result.slot = getelementptr i8, ptr %frame.addr, i64 16
  store i32 %result, ptr %result.slot, align 8
  %2 = getelementptr i8, ptr %frame.addr, i64 8
  %return.region.id = load i32, ptr %2, align 4
  %3 = getelementptr i8, ptr %frame.addr, i64 0
  %saved.fp = load i64, ptr %3, align 8
  %fiber.resume.region.id = getelementptr inbounds nuw %fiber_control, ptr %fiber_control, i32 0, i32 5
  store i32 %return.region.id, ptr %fiber.resume.region.id, align 4
  %return.sp = add i64 %frame.fp, 16
  %fiber.sp1 = getelementptr inbounds nuw %fiber_control, ptr %fiber_control, i32 0, i32 3
  store i64 %return.sp, ptr %fiber.sp1, align 8
  %fiber.fp2 = getelementptr inbounds nuw %fiber_control, ptr %fiber_control, i32 0, i32 4
  store i64 %saved.fp, ptr %fiber.fp2, align 8
  ret i32 0

context_helper.prologue.overflow:                 ; preds = %context_helper.prologue
  %fiber.outcome = getelementptr inbounds nuw %fiber_control, ptr %fiber_control, i32 0, i32 0
  %4 = call i32 @bpf_capsule_set_outcome(i32 %fiber, i64 -30064771069), !dbg !69
  ret i32 1

unit.dispatch1:                                   ; preds = %unit.dispatch
  br label %context_helper.prologue, !dbg !69
}

; Function Attrs: noinline
define i32 @__bpf_capsule_trampoline_step(i32 %fiber, ptr "bpf.capsule.control" %fiber_control) #2 !dbg !70 {
entry:
  %0 = icmp ne ptr %fiber_control, null, !dbg !74
  br i1 %0, label %control.ready, label %control.missing, !dbg !74

iterate:                                          ; preds = %control.ready
  %fiber.resume.region.id = getelementptr inbounds nuw %fiber_control, ptr %fiber_control, i32 0, i32 5, !dbg !74
  %resume.region.id = load i32, ptr %fiber.resume.region.id, align 4, !dbg !74
  %1 = icmp eq i32 %resume.region.id, -1, !dbg !74
  %2 = icmp eq i32 %resume.region.id, 0, !dbg !74
  %3 = or i1 %2, %1, !dbg !74
  br i1 %3, label %terminal, label %route, !dbg !74

control.ready:                                    ; preds = %entry
  br label %iterate, !dbg !74

control.missing:                                  ; preds = %entry
  ret i32 1, !dbg !74

route:                                            ; preds = %iterate
  br label %dispatch, !dbg !74

dispatch:                                         ; preds = %route
  %step.index = and i32 %resume.region.id, 255, !dbg !74
  %region.index = lshr i32 %resume.region.id, 8, !dbg !74
  switch i32 %step.index, label %bad.id [
    i32 0, label %bpf.dispatch.output.scalar.0
  ], !dbg !74

bpf.dispatch.output.scalar.0:                     ; preds = %dispatch
  %4 = call i32 @bpf.dispatch.output.scalar.0(i32 %fiber, ptr %fiber_control, i32 %region.index), !dbg !74
  ret i32 %4, !dbg !74

terminal:                                         ; preds = %iterate
  br i1 %1, label %completed, label %done, !dbg !74

completed:                                        ; preds = %terminal
  store i32 0, ptr %fiber.resume.region.id, align 4, !dbg !74
  br label %done, !dbg !74

done:                                             ; preds = %completed, %terminal
  ret i32 1, !dbg !74

bad.id:                                           ; preds = %dispatch
  %5 = call i32 @bpf_capsule_set_outcome(i32 %fiber, i64 -38654705661), !dbg !74
  ret i32 1, !dbg !74
}

; Function Attrs: noinline
define i32 @bpf.dispatch.output.scalar.0(i32 %fiber, ptr "bpf.capsule.control" %fiber_control, i32 %region) #1 !dbg !75 !bpf.capsule.flatten.root !51 {
entry:
  %0 = icmp ne ptr %fiber_control, null, !dbg !80
  br i1 %0, label %dispatch, label %bad.id, !dbg !80

dispatch:                                         ; preds = %entry
  switch i32 %region, label %bad.id [
    i32 1, label %bpf.unit.0
    i32 2, label %bpf.unit.0
    i32 3, label %bpf.unit.0
    i32 4, label %bpf.unit.0
    i32 5, label %bpf.unit.0
    i32 6, label %bpf.unit.1
  ], !dbg !80

bad.id:                                           ; preds = %dispatch, %entry
  %1 = call i32 @bpf_capsule_set_outcome(i32 %fiber, i64 -38654705661), !dbg !80
  ret i32 1, !dbg !80

bpf.unit.0:                                       ; preds = %dispatch, %dispatch, %dispatch, %dispatch, %dispatch
  %2 = call i32 @bpf.unit.0(i32 %fiber, ptr %fiber_control, i32 %region), !dbg !80
  ret i32 %2, !dbg !80

bpf.unit.1:                                       ; preds = %dispatch
  %3 = call i32 @bpf.unit.1(i32 %fiber, ptr %fiber_control, i32 %region), !dbg !80
  ret i32 %3, !dbg !80
}

; Function Attrs: noinline
define i32 @__bpf_capsule_trampoline_ctx_step(ptr "bpf.capsule.borrowed" %ctx, i32 %fiber, ptr "bpf.capsule.control" %fiber_control) #2 !dbg !81 {
entry:
  %0 = icmp ne ptr %fiber_control, null, !dbg !86
  br i1 %0, label %control.ready, label %control.missing, !dbg !86

iterate:                                          ; preds = %control.ready
  %fiber.resume.region.id = getelementptr inbounds nuw %fiber_control, ptr %fiber_control, i32 0, i32 5, !dbg !86
  %resume.region.id = load i32, ptr %fiber.resume.region.id, align 4, !dbg !86
  %1 = icmp eq i32 %resume.region.id, -1, !dbg !86
  %2 = icmp eq i32 %resume.region.id, 0, !dbg !86
  %3 = or i1 %2, %1, !dbg !86
  br i1 %3, label %terminal, label %route, !dbg !86

control.ready:                                    ; preds = %entry
  br label %iterate, !dbg !86

control.missing:                                  ; preds = %entry
  ret i32 1, !dbg !86

route:                                            ; preds = %iterate
  br label %dispatch, !dbg !86

dispatch:                                         ; preds = %route
  %step.index = and i32 %resume.region.id, 255, !dbg !86
  %region.index = lshr i32 %resume.region.id, 8, !dbg !86
  switch i32 %step.index, label %bad.id [
    i32 1, label %bpf.dispatch.output.ctx.0
    i32 0, label %scalar.root.0
  ], !dbg !86

bpf.dispatch.output.ctx.0:                        ; preds = %dispatch
  %4 = call i32 @bpf.dispatch.output.ctx.0(ptr %ctx, i32 %fiber, ptr %fiber_control, i32 %region.index), !dbg !86
  ret i32 %4, !dbg !86

terminal:                                         ; preds = %iterate
  br i1 %1, label %completed, label %done, !dbg !86

completed:                                        ; preds = %terminal
  store i32 0, ptr %fiber.resume.region.id, align 4, !dbg !86
  br label %done, !dbg !86

scalar.root.0:                                    ; preds = %dispatch
  %5 = call i32 @bpf.dispatch.output.scalar.0(i32 %fiber, ptr %fiber_control, i32 %region.index), !dbg !86
  ret i32 %5, !dbg !86

done:                                             ; preds = %completed, %terminal
  ret i32 1, !dbg !86

bad.id:                                           ; preds = %dispatch
  %6 = call i32 @bpf_capsule_set_outcome(i32 %fiber, i64 -38654705661), !dbg !86
  ret i32 1, !dbg !86
}

; Function Attrs: noinline
define i32 @bpf.dispatch.output.ctx.0(ptr "bpf.capsule.borrowed" %ctx, i32 %fiber, ptr "bpf.capsule.control" %fiber_control, i32 %region) #1 !dbg !87 !bpf.capsule.flatten.root !68 {
entry:
  %0 = icmp ne ptr %fiber_control, null, !dbg !93
  br i1 %0, label %dispatch, label %bad.id, !dbg !93

dispatch:                                         ; preds = %entry
  switch i32 %region, label %bad.id [
    i32 1, label %bpf.unit.2
  ], !dbg !93

bad.id:                                           ; preds = %dispatch, %entry
  %1 = call i32 @bpf_capsule_set_outcome(i32 %fiber, i64 -38654705661), !dbg !93
  ret i32 1, !dbg !93

bpf.unit.2:                                       ; preds = %dispatch
  %2 = call i32 @bpf.unit.2(ptr %ctx, i32 %fiber, ptr %fiber_control, i32 %region), !dbg !93
  ret i32 %2, !dbg !93
}

attributes #0 = { "capsule.trampoline" }
attributes #1 = { noinline }
attributes #2 = { noinline "capsule.trampoline" }

!llvm.dbg.cu = !{!1}
!llvm.module.flags = !{!3, !4, !5}

!0 = !{i64 262144}
!1 = distinct !DICompileUnit(language: DW_LANG_C11, file: !2, producer: "pass contract", isOptimized: false, runtimeVersion: 0, emissionKind: FullDebug)
!2 = !DIFile(filename: "stackify-borrowed-context.c", directory: "/")
!3 = !{i32 7, !"Dwarf Version", i32 5}
!4 = !{i32 2, !"Debug Info Version", i32 3}
!5 = !{i32 1, !"bpf.capsule.classes", i32 1}
!6 = distinct !DISubprogram(name: "__bpf_capsule_trampoline_l1", linkageName: "__bpf_capsule_trampoline_l1", scope: null, file: !2, type: !7, spFlags: DISPFlagDefinition, unit: !1, retainedNodes: !16)
!7 = !DISubroutineType(types: !8)
!8 = !{!9, !10, !11}
!9 = !DIBasicType(name: "int", size: 32, encoding: DW_ATE_signed)
!10 = !DIBasicType(name: "unsigned int", size: 32, encoding: DW_ATE_unsigned)
!11 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !12, size: 64)
!12 = !DICompositeType(tag: DW_TAG_array_type, baseType: !13, size: 320, align: 8, elements: !14)
!13 = !DIBasicType(name: "unsigned char", size: 8, encoding: DW_ATE_unsigned_char)
!14 = !{!15}
!15 = !DISubrange(count: 40, lowerBound: 0)
!16 = !{!17, !18}
!17 = !DILocalVariable(name: "fiber", arg: 1, scope: !6, file: !2, type: !10)
!18 = !DILocalVariable(name: "control", arg: 2, scope: !6, file: !2, type: !11)
!19 = !DILocation(line: 0, scope: !6)
!20 = distinct !DISubprogram(name: "__bpf_capsule_trampoline_ctx_l1", linkageName: "__bpf_capsule_trampoline_ctx_l1", scope: null, file: !2, type: !21, spFlags: DISPFlagDefinition, unit: !1, retainedNodes: !25)
!21 = !DISubroutineType(types: !22)
!22 = !{!9, !23, !10, !11}
!23 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !24, size: 64)
!24 = distinct !DICompositeType(tag: DW_TAG_structure_type, name: "xdp_md", file: !2, size: 192)
!25 = !{!26, !27, !28}
!26 = !DILocalVariable(name: "context", arg: 1, scope: !20, file: !2, type: !23)
!27 = !DILocalVariable(name: "fiber", arg: 2, scope: !20, file: !2, type: !10)
!28 = !DILocalVariable(name: "control", arg: 3, scope: !20, file: !2, type: !11)
!29 = !DILocation(line: 0, scope: !20)
!30 = distinct !DISubprogram(name: "start", scope: !2, file: !2, type: !31, spFlags: DISPFlagDefinition, unit: !1)
!31 = !DISubroutineType(types: !32)
!32 = !{!9, !23, !9}
!33 = !{}
!34 = !DILocation(line: 0, scope: !30)
!35 = distinct !DISubprogram(name: "bpf_capsule_set_outcome", linkageName: "bpf_capsule_set_outcome", scope: null, file: !2, type: !36, spFlags: DISPFlagDefinition, unit: !1, retainedNodes: !39)
!36 = !DISubroutineType(types: !37)
!37 = !{!9, !9, !38}
!38 = !DIBasicType(name: "long long", size: 64, encoding: DW_ATE_signed)
!39 = !{!40, !41}
!40 = !DILocalVariable(name: "a0", arg: 1, scope: !35, file: !2, type: !9)
!41 = !DILocalVariable(name: "a1", arg: 2, scope: !35, file: !2, type: !38)
!42 = !DILocation(line: 0, scope: !35)
!43 = distinct !DISubprogram(name: "bpf.unit.0", linkageName: "bpf.unit.0", scope: null, file: !2, type: !44, flags: DIFlagArtificial, spFlags: DISPFlagDefinition, unit: !1, retainedNodes: !46)
!44 = !DISubroutineType(types: !45)
!45 = !{!9, !10, !11, !10}
!46 = !{!47, !48, !49}
!47 = !DILocalVariable(name: "fiber", arg: 1, scope: !43, file: !2, type: !10)
!48 = !DILocalVariable(name: "fiber_control", arg: 2, scope: !43, file: !2, type: !11)
!49 = !DILocalVariable(name: "region", arg: 3, scope: !43, file: !2, type: !10)
!50 = !{i32 0}
!51 = !{i32 2}
!52 = !DILocation(line: 0, scope: !43)
!53 = distinct !DISubprogram(name: "bpf.unit.1", linkageName: "bpf.unit.1", scope: null, file: !2, type: !44, flags: DIFlagArtificial, spFlags: DISPFlagDefinition, unit: !1, retainedNodes: !54)
!54 = !{!55, !56, !57}
!55 = !DILocalVariable(name: "fiber", arg: 1, scope: !53, file: !2, type: !10)
!56 = !DILocalVariable(name: "fiber_control", arg: 2, scope: !53, file: !2, type: !11)
!57 = !DILocalVariable(name: "region", arg: 3, scope: !53, file: !2, type: !10)
!58 = !DILocation(line: 0, scope: !53)
!59 = distinct !DISubprogram(name: "bpf.unit.2", linkageName: "bpf.unit.2", scope: null, file: !2, type: !60, flags: DIFlagArtificial, spFlags: DISPFlagDefinition, unit: !1, retainedNodes: !62)
!60 = !DISubroutineType(types: !61)
!61 = !{!9, !23, !10, !11, !10}
!62 = !{!63, !64, !65, !66}
!63 = !DILocalVariable(name: "ctx", arg: 1, scope: !59, file: !2, type: !23)
!64 = !DILocalVariable(name: "fiber", arg: 2, scope: !59, file: !2, type: !10)
!65 = !DILocalVariable(name: "fiber_control", arg: 3, scope: !59, file: !2, type: !11)
!66 = !DILocalVariable(name: "region", arg: 4, scope: !59, file: !2, type: !10)
!67 = !{i32 1}
!68 = !{i32 3}
!69 = !DILocation(line: 0, scope: !59)
!70 = distinct !DISubprogram(name: "__bpf_capsule_trampoline_step", linkageName: "__bpf_capsule_trampoline_step", scope: null, file: !2, type: !7, spFlags: DISPFlagDefinition, unit: !1, retainedNodes: !71)
!71 = !{!72, !73}
!72 = !DILocalVariable(name: "fiber", arg: 1, scope: !70, file: !2, type: !10)
!73 = !DILocalVariable(name: "fiber_control", arg: 2, scope: !70, file: !2, type: !11)
!74 = !DILocation(line: 0, scope: !70)
!75 = distinct !DISubprogram(name: "bpf.dispatch.output.scalar.0", linkageName: "bpf.dispatch.output.scalar.0", scope: null, file: !2, type: !44, spFlags: DISPFlagDefinition, unit: !1, retainedNodes: !76)
!76 = !{!77, !78, !79}
!77 = !DILocalVariable(name: "fiber", arg: 1, scope: !75, file: !2, type: !10)
!78 = !DILocalVariable(name: "fiber_control", arg: 2, scope: !75, file: !2, type: !11)
!79 = !DILocalVariable(name: "region", arg: 3, scope: !75, file: !2, type: !10)
!80 = !DILocation(line: 0, scope: !75)
!81 = distinct !DISubprogram(name: "__bpf_capsule_trampoline_ctx_step", linkageName: "__bpf_capsule_trampoline_ctx_step", scope: null, file: !2, type: !21, spFlags: DISPFlagDefinition, unit: !1, retainedNodes: !82)
!82 = !{!83, !84, !85}
!83 = !DILocalVariable(name: "ctx", arg: 1, scope: !81, file: !2, type: !23)
!84 = !DILocalVariable(name: "fiber", arg: 2, scope: !81, file: !2, type: !10)
!85 = !DILocalVariable(name: "fiber_control", arg: 3, scope: !81, file: !2, type: !11)
!86 = !DILocation(line: 0, scope: !81)
!87 = distinct !DISubprogram(name: "bpf.dispatch.output.ctx.0", linkageName: "bpf.dispatch.output.ctx.0", scope: null, file: !2, type: !60, spFlags: DISPFlagDefinition, unit: !1, retainedNodes: !88)
!88 = !{!89, !90, !91, !92}
!89 = !DILocalVariable(name: "ctx", arg: 1, scope: !87, file: !2, type: !23)
!90 = !DILocalVariable(name: "fiber", arg: 2, scope: !87, file: !2, type: !10)
!91 = !DILocalVariable(name: "fiber_control", arg: 3, scope: !87, file: !2, type: !11)
!92 = !DILocalVariable(name: "region", arg: 4, scope: !87, file: !2, type: !10)
!93 = !DILocation(line: 0, scope: !87)
