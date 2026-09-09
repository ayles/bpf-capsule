source_filename = "stackify-borrowed-context.ll"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpfel"

%fiber_control = type { i32, i32, i64, i64, i64, i32, i32 }
%config = type { i32, i32, i32, i32, i32, i32, i32, i32, i32, i32, i32, i32, i64 }

@bpf_capsule_fibers = global [1 x %fiber_control] zeroinitializer, section ".bss.bpfctrl", align 8
@bpf_capsule_config = constant %config { i32 0, i32 4096, i32 0, i32 0, i32 1, i32 4096, i32 1, i32 0, i32 1, i32 0, i32 1112556353, i32 8, i64 0 }, section ".rodata.bpfconfig", align 4
@bpf_call_stack = internal global [262144 x i8] zeroinitializer, align 262144, !bpf.fiber.stack.size !0

define i32 @__bpf_capsule_trampoline_l1(i32 %fiber, ptr nonnull %control) #0 !dbg !6 {
entry:
  %status = call i32 @__bpf_capsule_trampoline_step(i32 %fiber, ptr %control), !dbg !21
  ret i32 %status, !dbg !21
}

define i32 @__bpf_capsule_trampoline(i32 %fiber) #0 {
entry:
  %control = getelementptr [1 x %fiber_control], ptr @bpf_capsule_fibers, i32 0, i32 %fiber
  %status = call i32 @__bpf_capsule_trampoline_l1(i32 %fiber, ptr %control)
  ret i32 %status
}

define i32 @__bpf_capsule_trampoline_ctx_l1(ptr %context, i32 %fiber, ptr nonnull %control) #0 !dbg !22 {
entry:
  %status = call i32 @__bpf_capsule_trampoline_ctx_step(ptr %context, i32 %fiber, ptr %control), !dbg !31
  ret i32 %status, !dbg !31
}

define i32 @__bpf_capsule_trampoline_ctx(ptr %context, i32 %fiber) #0 {
entry:
  %control = getelementptr [1 x %fiber_control], ptr @bpf_capsule_fibers, i32 0, i32 %fiber
  %status = call i32 @__bpf_capsule_trampoline_ctx_l1(ptr %context, i32 %fiber, ptr %control)
  ret i32 %status
}

define i32 @start(ptr %context, i32 %fiber) section "xdp" !dbg !32 !bpf.native !35 {
entry:
  %fiber.index = and i32 %fiber, 0
  %fiber.index1 = and i32 %fiber.index, 0
  %0 = zext i32 %fiber.index1 to i64
  %1 = mul i64 %0, 262144
  %stack.linear.offset = add i64 %1, 262112
  %fiber.stack = getelementptr i8, ptr @bpf_call_stack, i64 %stack.linear.offset
  %root.fp = ptrtoint ptr %fiber.stack to i64
  %fiber.index2 = and i32 %fiber.index, 0
  %fiber.control = getelementptr inbounds [1 x %fiber_control], ptr @bpf_capsule_fibers, i32 0, i32 %fiber.index2, !bpf.capsule.sectioned.bounded !35
  %fiber.outcome = getelementptr inbounds nuw %fiber_control, ptr %fiber.control, i32 0, i32 0
  store i64 0, ptr %fiber.outcome, align 8
  %root.saved.fp = getelementptr i8, ptr %fiber.stack, i64 0
  store i64 0, ptr %root.saved.fp, align 8
  %root.return.region.id = getelementptr i8, ptr %fiber.stack, i64 8
  store i32 -1, ptr %root.return.region.id, align 4
  %fiber.index3 = and i32 %fiber.index, 0
  %fiber.control4 = getelementptr inbounds [1 x %fiber_control], ptr @bpf_capsule_fibers, i32 0, i32 %fiber.index3, !bpf.capsule.sectioned.bounded !35
  %fiber.return.size = getelementptr inbounds nuw %fiber_control, ptr %fiber.control4, i32 0, i32 6
  store i32 4, ptr %fiber.return.size, align 4
  %fiber.index5 = and i32 %fiber.index, 0
  %fiber.control6 = getelementptr inbounds [1 x %fiber_control], ptr @bpf_capsule_fibers, i32 0, i32 %fiber.index5, !bpf.capsule.sectioned.bounded !35
  %fiber.resume.region.id = getelementptr inbounds nuw %fiber_control, ptr %fiber.control6, i32 0, i32 5
  store i32 256, ptr %fiber.resume.region.id, align 4
  %fiber.index7 = and i32 %fiber.index, 0
  %fiber.control8 = getelementptr inbounds [1 x %fiber_control], ptr @bpf_capsule_fibers, i32 0, i32 %fiber.index7, !bpf.capsule.sectioned.bounded !35
  %fiber.sp = getelementptr inbounds nuw %fiber_control, ptr %fiber.control8, i32 0, i32 3
  store i64 %root.fp, ptr %fiber.sp, align 8
  %fiber.index9 = and i32 %fiber.index, 0
  %fiber.control10 = getelementptr inbounds [1 x %fiber_control], ptr @bpf_capsule_fibers, i32 0, i32 %fiber.index9, !bpf.capsule.sectioned.bounded !35
  %fiber.fp = getelementptr inbounds nuw %fiber_control, ptr %fiber.control10, i32 0, i32 4
  store i64 %root.fp, ptr %fiber.fp, align 8
  %control.i = getelementptr [1 x %fiber_control], ptr @bpf_capsule_fibers, i32 0, i32 %fiber.index
  %status.i = call i32 @__bpf_capsule_trampoline_ctx_l1(ptr %context, i32 %fiber.index, ptr %control.i), !dbg !36
  %fiber.index11 = and i32 %fiber.index, 0
  %2 = zext i32 %fiber.index11 to i64
  %3 = mul i64 %2, 262144
  %stack.linear.offset12 = add i64 %3, 262128
  %fiber.stack13 = getelementptr i8, ptr @bpf_call_stack, i64 %stack.linear.offset12
  %root.result = load i32, ptr %fiber.stack13, align 8
  ret i32 %root.result
}

define i32 @start_scalar(i32 %fiber) section "syscall" !bpf.native !35 {
entry:
  %fiber.index = and i32 %fiber, 0
  %fiber.index1 = and i32 %fiber.index, 0
  %0 = zext i32 %fiber.index1 to i64
  %1 = mul i64 %0, 262144
  %stack.linear.offset = add i64 %1, 262112
  %fiber.stack = getelementptr i8, ptr @bpf_call_stack, i64 %stack.linear.offset
  %root.fp = ptrtoint ptr %fiber.stack to i64
  %fiber.index2 = and i32 %fiber.index, 0
  %fiber.control = getelementptr inbounds [1 x %fiber_control], ptr @bpf_capsule_fibers, i32 0, i32 %fiber.index2, !bpf.capsule.sectioned.bounded !35
  %fiber.outcome = getelementptr inbounds nuw %fiber_control, ptr %fiber.control, i32 0, i32 0
  store i64 0, ptr %fiber.outcome, align 8
  %root.saved.fp = getelementptr i8, ptr %fiber.stack, i64 0
  store i64 0, ptr %root.saved.fp, align 8
  %root.return.region.id = getelementptr i8, ptr %fiber.stack, i64 8
  store i32 -1, ptr %root.return.region.id, align 4
  %2 = getelementptr i8, ptr %fiber.stack, i64 24
  store i32 5, ptr %2, align 8
  %fiber.index3 = and i32 %fiber.index, 0
  %fiber.control4 = getelementptr inbounds [1 x %fiber_control], ptr @bpf_capsule_fibers, i32 0, i32 %fiber.index3, !bpf.capsule.sectioned.bounded !35
  %fiber.return.size = getelementptr inbounds nuw %fiber_control, ptr %fiber.control4, i32 0, i32 6
  store i32 4, ptr %fiber.return.size, align 4
  %fiber.index5 = and i32 %fiber.index, 0
  %fiber.control6 = getelementptr inbounds [1 x %fiber_control], ptr @bpf_capsule_fibers, i32 0, i32 %fiber.index5, !bpf.capsule.sectioned.bounded !35
  %fiber.resume.region.id = getelementptr inbounds nuw %fiber_control, ptr %fiber.control6, i32 0, i32 5
  store i32 1536, ptr %fiber.resume.region.id, align 4
  %fiber.index7 = and i32 %fiber.index, 0
  %fiber.control8 = getelementptr inbounds [1 x %fiber_control], ptr @bpf_capsule_fibers, i32 0, i32 %fiber.index7, !bpf.capsule.sectioned.bounded !35
  %fiber.sp = getelementptr inbounds nuw %fiber_control, ptr %fiber.control8, i32 0, i32 3
  store i64 %root.fp, ptr %fiber.sp, align 8
  %fiber.index9 = and i32 %fiber.index, 0
  %fiber.control10 = getelementptr inbounds [1 x %fiber_control], ptr @bpf_capsule_fibers, i32 0, i32 %fiber.index9, !bpf.capsule.sectioned.bounded !35
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
define i32 @bpf_capsule_set_outcome(i32 %fiber, i64 %outcome) #1 !dbg !37 !bpf.native.scalar !35 {
entry:
  %fiber.index = and i32 %fiber, 0, !dbg !44
  %fiber.control = getelementptr inbounds [1 x %fiber_control], ptr @bpf_capsule_fibers, i32 0, i32 %fiber.index, !dbg !44, !bpf.capsule.sectioned.bounded !35
  %fiber.outcome = getelementptr inbounds nuw %fiber_control, ptr %fiber.control, i32 0, i32 0, !dbg !44
  store volatile i64 %outcome, ptr %fiber.outcome, align 8, !dbg !44
  ret i32 0, !dbg !44
}

; Function Attrs: noinline
define i32 @bpf.unit.0(i32 %fiber, ptr "bpf.capsule.control" %fiber_control, i32 %region) #1 !dbg !45 !bpf.capsule !35 !bpf.capsule.allocation.unit !52 !bpf.capsule.stack.size !0 !bpf.capsule.flatten.unit !53 {
unit.entry:
  %fiber.fp = getelementptr inbounds nuw %fiber_control, ptr %fiber_control, i32 0, i32 4
  %frame.fp = load i64, ptr %fiber.fp, align 8
  %frame.addr = inttoptr i64 %frame.fp to ptr
  call void asm sideeffect "# bpf_capsule_stack_anchor", "r"(ptr %fiber_control), !dbg !54
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
  %2 = call i32 @bpf_capsule_set_outcome(i32 %fiber, i64 -30064771069), !dbg !54
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
  %8 = icmp ult i32 %region, 768, !dbg !54
  br i1 %8, label %unit.test.left, label %unit.test.right, !dbg !54

unit.test.left:                                   ; preds = %unit.dispatch1
  %9 = icmp ult i32 %region, 512
  br i1 %9, label %unit.test.left2, label %unit.test.right3

unit.test.right:                                  ; preds = %unit.dispatch1
  %10 = icmp ult i32 %region, 1024
  br i1 %10, label %unit.test.left4, label %unit.test.right5

unit.test.left2:                                  ; preds = %unit.test.left
  br label %borrowed_root.prologue

unit.test.right3:                                 ; preds = %unit.test.left
  br label %entry.resume

unit.test.left4:                                  ; preds = %unit.test.right
  br label %entry.resume.resume

unit.test.right5:                                 ; preds = %unit.test.right
  %11 = icmp ult i32 %region, 1280
  br i1 %11, label %unit.test.left6, label %unit.test.right7

unit.test.left6:                                  ; preds = %unit.test.right5
  br label %entry.resume.resume.resume

unit.test.right7:                                 ; preds = %unit.test.right5
  br label %entry.resume.resume.resume.resume
}

; Function Attrs: noinline
define i32 @bpf.unit.1(i32 %fiber, ptr "bpf.capsule.control" %fiber_control, i32 %region) #1 !dbg !55 !bpf.capsule !35 !bpf.capsule.allocation.unit !52 !bpf.capsule.stack.size !0 !bpf.capsule.flatten.unit !53 {
unit.entry:
  %fiber.fp = getelementptr inbounds nuw %fiber_control, ptr %fiber_control, i32 0, i32 4
  %frame.fp = load i64, ptr %fiber.fp, align 8
  %frame.addr = inttoptr i64 %frame.fp to ptr
  call void asm sideeffect "# bpf_capsule_stack_anchor", "r"(ptr %fiber_control), !dbg !60
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
  %4 = call i32 @bpf_capsule_set_outcome(i32 %fiber, i64 -30064771069), !dbg !60
  ret i32 1

unit.dispatch1:                                   ; preds = %unit.dispatch
  br label %scalar_helper.prologue, !dbg !60
}

; Function Attrs: noinline
define i32 @bpf.unit.2(ptr "bpf.capsule.borrowed" %ctx, i32 %fiber, ptr "bpf.capsule.control" %fiber_control, i32 %region) #1 !dbg !61 !bpf.capsule !35 !bpf.capsule.allocation.unit !69 !bpf.capsule.stack.size !0 !bpf.capsule.flatten.unit !70 {
unit.entry:
  %fiber.fp = getelementptr inbounds nuw %fiber_control, ptr %fiber_control, i32 0, i32 4
  %frame.fp = load i64, ptr %fiber.fp, align 8
  %frame.addr = inttoptr i64 %frame.fp to ptr
  call void asm sideeffect "# bpf_capsule_stack_anchor", "r"(ptr %fiber_control), !dbg !71
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
  call void asm sideeffect "", "r"(ptr %ctx), !dbg !71
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
  %4 = call i32 @bpf_capsule_set_outcome(i32 %fiber, i64 -30064771069), !dbg !71
  ret i32 1

unit.dispatch1:                                   ; preds = %unit.dispatch
  br label %context_helper.prologue, !dbg !71
}

; Function Attrs: noinline
define i32 @__bpf_capsule_trampoline_step(i32 %fiber, ptr nonnull "bpf.capsule.control" %fiber_control) #2 !dbg !72 {
entry:
  %0 = icmp ne ptr %fiber_control, null, !dbg !76
  br i1 %0, label %control.ready, label %control.missing, !dbg !76

iterate:                                          ; preds = %latch, %control.ready
  %trip = phi i32 [ 0, %control.ready ], [ %trip.next, %latch ], !dbg !76
  %fiber.resume.region.id = getelementptr inbounds nuw %fiber_control, ptr %fiber_control, i32 0, i32 5, !dbg !76
  %resume.region.id = load i32, ptr %fiber.resume.region.id, align 4, !dbg !76
  %1 = icmp eq i32 %resume.region.id, -1, !dbg !76
  %2 = icmp eq i32 %resume.region.id, 0, !dbg !76
  %3 = or i1 %2, %1, !dbg !76
  br label %route, !dbg !76

control.ready:                                    ; preds = %entry
  br label %iterate, !dbg !76

control.missing:                                  ; preds = %entry
  ret i32 1, !dbg !76

route:                                            ; preds = %iterate
  br label %dispatch, !dbg !76

dispatch:                                         ; preds = %route
  %step.index = and i32 %resume.region.id, 255, !dbg !76
  %region.key = and i32 %resume.region.id, 16776960, !dbg !76
  switch i32 %step.index, label %bad.id [
    i32 0, label %idle.or.root
    i32 255, label %completed
  ], !dbg !76

idle.or.root:                                     ; preds = %dispatch
  br i1 %2, label %done, label %bpf.dispatch.output.scalar.0, !dbg !76

bpf.dispatch.output.scalar.0:                     ; preds = %idle.or.root
  %4 = call i32 @bpf.dispatch.output.scalar.0(i32 %fiber, ptr %fiber_control, i32 %region.key), !dbg !76
  %5 = icmp ne i32 %4, 0, !dbg !76
  br i1 %5, label %bpf.dispatch.output.scalar.0.stop, label %latch, !dbg !76

bpf.dispatch.output.scalar.0.stop:                ; preds = %bpf.dispatch.output.scalar.0
  ret i32 %4, !dbg !76

terminal:                                         ; No predecessors!
  br i1 %1, label %completed, label %done, !dbg !76

completed:                                        ; preds = %terminal, %dispatch
  store i32 0, ptr %fiber.resume.region.id, align 4, !dbg !76
  br label %done, !dbg !76

done:                                             ; preds = %completed, %terminal, %idle.or.root
  ret i32 1, !dbg !76

bad.id:                                           ; preds = %dispatch
  %6 = call i32 @bpf_capsule_set_outcome(i32 %fiber, i64 -38654705661), !dbg !76
  ret i32 1, !dbg !76

latch:                                            ; preds = %bpf.dispatch.output.scalar.0
  %trip.next = add i32 %trip, 1, !dbg !76
  %7 = icmp ult i32 %trip.next, 32, !dbg !76
  br i1 %7, label %iterate, label %exhausted, !dbg !76

exhausted:                                        ; preds = %latch
  ret i32 0, !dbg !76
}

; Function Attrs: noinline
define i32 @bpf.dispatch.output.scalar.0(i32 %fiber, ptr nonnull "bpf.capsule.control" %fiber_control, i32 %region) #1 !dbg !77 !bpf.capsule.flatten.root !53 {
entry:
  %0 = icmp ne ptr %fiber_control, null, !dbg !82
  br i1 %0, label %dispatch, label %bad.id, !dbg !82

dispatch:                                         ; preds = %entry
  br label %unit.route, !dbg !82

unit.route:                                       ; preds = %dispatch
  %1 = icmp ult i32 %region, 1536, !dbg !82
  br i1 %1, label %unit.route.left, label %unit.route.right, !dbg !82

unit.route.left:                                  ; preds = %unit.route
  br label %bpf.unit.0, !dbg !82

unit.route.right:                                 ; preds = %unit.route
  br label %bpf.unit.1, !dbg !82

bad.id:                                           ; preds = %entry
  %2 = call i32 @bpf_capsule_set_outcome(i32 %fiber, i64 -38654705661), !dbg !82
  ret i32 1, !dbg !82

bpf.unit.0:                                       ; preds = %unit.route.left
  %3 = call i32 @bpf.unit.0(i32 %fiber, ptr %fiber_control, i32 %region), !dbg !82
  ret i32 %3, !dbg !82

bpf.unit.1:                                       ; preds = %unit.route.right
  %4 = call i32 @bpf.unit.1(i32 %fiber, ptr %fiber_control, i32 %region), !dbg !82
  ret i32 %4, !dbg !82
}

; Function Attrs: noinline
define i32 @__bpf_capsule_trampoline_ctx_step(ptr "bpf.capsule.borrowed" %ctx, i32 %fiber, ptr nonnull "bpf.capsule.control" %fiber_control) #2 !dbg !83 {
entry:
  %0 = icmp ne ptr %fiber_control, null, !dbg !88
  br i1 %0, label %control.ready, label %control.missing, !dbg !88

iterate:                                          ; preds = %latch, %control.ready
  %trip = phi i32 [ 0, %control.ready ], [ %trip.next, %latch ], !dbg !88
  %fiber.resume.region.id = getelementptr inbounds nuw %fiber_control, ptr %fiber_control, i32 0, i32 5, !dbg !88
  %resume.region.id = load i32, ptr %fiber.resume.region.id, align 4, !dbg !88
  %1 = icmp eq i32 %resume.region.id, -1, !dbg !88
  %2 = icmp eq i32 %resume.region.id, 0, !dbg !88
  %3 = or i1 %2, %1, !dbg !88
  br label %route, !dbg !88

control.ready:                                    ; preds = %entry
  br label %iterate, !dbg !88

control.missing:                                  ; preds = %entry
  ret i32 1, !dbg !88

route:                                            ; preds = %iterate
  br label %dispatch, !dbg !88

dispatch:                                         ; preds = %route
  %step.index = and i32 %resume.region.id, 255, !dbg !88
  %region.key = and i32 %resume.region.id, 16776960, !dbg !88
  switch i32 %step.index, label %bad.id [
    i32 1, label %bpf.dispatch.output.ctx.0
    i32 0, label %idle.or.root
    i32 255, label %completed
  ], !dbg !88

bpf.dispatch.output.ctx.0:                        ; preds = %dispatch
  %4 = call i32 @bpf.dispatch.output.ctx.0(ptr %ctx, i32 %fiber, ptr %fiber_control, i32 %region.key), !dbg !88
  %5 = icmp ne i32 %4, 0, !dbg !88
  br i1 %5, label %bpf.dispatch.output.ctx.0.stop, label %latch, !dbg !88

bpf.dispatch.output.ctx.0.stop:                   ; preds = %bpf.dispatch.output.ctx.0
  ret i32 %4, !dbg !88

scalar.root.0.stop:                               ; preds = %scalar.root.0
  ret i32 %6, !dbg !88

terminal:                                         ; No predecessors!
  br i1 %1, label %completed, label %done, !dbg !88

completed:                                        ; preds = %terminal, %dispatch
  store i32 0, ptr %fiber.resume.region.id, align 4, !dbg !88
  br label %done, !dbg !88

idle.or.root:                                     ; preds = %dispatch
  br i1 %2, label %done, label %scalar.root.0, !dbg !88

scalar.root.0:                                    ; preds = %idle.or.root
  %6 = call i32 @bpf.dispatch.output.scalar.0(i32 %fiber, ptr %fiber_control, i32 %region.key), !dbg !88
  %7 = icmp ne i32 %6, 0, !dbg !88
  br i1 %7, label %scalar.root.0.stop, label %latch, !dbg !88

done:                                             ; preds = %idle.or.root, %completed, %terminal
  ret i32 1, !dbg !88

bad.id:                                           ; preds = %dispatch
  %8 = call i32 @bpf_capsule_set_outcome(i32 %fiber, i64 -38654705661), !dbg !88
  ret i32 1, !dbg !88

latch:                                            ; preds = %scalar.root.0, %bpf.dispatch.output.ctx.0
  %trip.next = add i32 %trip, 1, !dbg !88
  %9 = icmp ult i32 %trip.next, 32, !dbg !88
  br i1 %9, label %iterate, label %exhausted, !dbg !88

exhausted:                                        ; preds = %latch
  ret i32 0, !dbg !88
}

; Function Attrs: noinline
define i32 @bpf.dispatch.output.ctx.0(ptr "bpf.capsule.borrowed" %ctx, i32 %fiber, ptr nonnull "bpf.capsule.control" %fiber_control, i32 %region) #1 !dbg !89 !bpf.capsule.flatten.root !70 {
entry:
  %0 = icmp ne ptr %fiber_control, null, !dbg !95
  br i1 %0, label %dispatch, label %bad.id, !dbg !95

dispatch:                                         ; preds = %entry
  br label %unit.route, !dbg !95

unit.route:                                       ; preds = %dispatch
  br label %bpf.unit.2, !dbg !95

bad.id:                                           ; preds = %entry
  %1 = call i32 @bpf_capsule_set_outcome(i32 %fiber, i64 -38654705661), !dbg !95
  ret i32 1, !dbg !95

bpf.unit.2:                                       ; preds = %unit.route
  %2 = call i32 @bpf.unit.2(ptr %ctx, i32 %fiber, ptr %fiber_control, i32 %region), !dbg !95
  ret i32 %2, !dbg !95
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
!18 = !DILocalVariable(name: "control", arg: 2, scope: !6, file: !2, type: !11, annotations: !19)
!19 = !{!20}
!20 = !{!"btf_decl_tag", !"arg:nonnull"}
!21 = !DILocation(line: 0, scope: !6)
!22 = distinct !DISubprogram(name: "__bpf_capsule_trampoline_ctx_l1", linkageName: "__bpf_capsule_trampoline_ctx_l1", scope: null, file: !2, type: !23, spFlags: DISPFlagDefinition, unit: !1, retainedNodes: !27)
!23 = !DISubroutineType(types: !24)
!24 = !{!9, !25, !10, !11}
!25 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !26, size: 64)
!26 = distinct !DICompositeType(tag: DW_TAG_structure_type, name: "xdp_md", file: !2, size: 192)
!27 = !{!28, !29, !30}
!28 = !DILocalVariable(name: "context", arg: 1, scope: !22, file: !2, type: !25)
!29 = !DILocalVariable(name: "fiber", arg: 2, scope: !22, file: !2, type: !10)
!30 = !DILocalVariable(name: "control", arg: 3, scope: !22, file: !2, type: !11, annotations: !19)
!31 = !DILocation(line: 0, scope: !22)
!32 = distinct !DISubprogram(name: "start", scope: !2, file: !2, type: !33, spFlags: DISPFlagDefinition, unit: !1)
!33 = !DISubroutineType(types: !34)
!34 = !{!9, !25, !9}
!35 = !{}
!36 = !DILocation(line: 0, scope: !32)
!37 = distinct !DISubprogram(name: "bpf_capsule_set_outcome", linkageName: "bpf_capsule_set_outcome", scope: null, file: !2, type: !38, spFlags: DISPFlagDefinition, unit: !1, retainedNodes: !41)
!38 = !DISubroutineType(types: !39)
!39 = !{!9, !9, !40}
!40 = !DIBasicType(name: "long long", size: 64, encoding: DW_ATE_signed)
!41 = !{!42, !43}
!42 = !DILocalVariable(name: "a0", arg: 1, scope: !37, file: !2, type: !9)
!43 = !DILocalVariable(name: "a1", arg: 2, scope: !37, file: !2, type: !40)
!44 = !DILocation(line: 0, scope: !37)
!45 = distinct !DISubprogram(name: "bpf.unit.0", linkageName: "bpf.unit.0", scope: null, file: !2, type: !46, flags: DIFlagArtificial, spFlags: DISPFlagDefinition, unit: !1, retainedNodes: !48)
!46 = !DISubroutineType(types: !47)
!47 = !{!9, !10, !11, !10}
!48 = !{!49, !50, !51}
!49 = !DILocalVariable(name: "fiber", arg: 1, scope: !45, file: !2, type: !10)
!50 = !DILocalVariable(name: "fiber_control", arg: 2, scope: !45, file: !2, type: !11)
!51 = !DILocalVariable(name: "region", arg: 3, scope: !45, file: !2, type: !10)
!52 = !{i32 0}
!53 = !{i32 2}
!54 = !DILocation(line: 0, scope: !45)
!55 = distinct !DISubprogram(name: "bpf.unit.1", linkageName: "bpf.unit.1", scope: null, file: !2, type: !46, flags: DIFlagArtificial, spFlags: DISPFlagDefinition, unit: !1, retainedNodes: !56)
!56 = !{!57, !58, !59}
!57 = !DILocalVariable(name: "fiber", arg: 1, scope: !55, file: !2, type: !10)
!58 = !DILocalVariable(name: "fiber_control", arg: 2, scope: !55, file: !2, type: !11)
!59 = !DILocalVariable(name: "region", arg: 3, scope: !55, file: !2, type: !10)
!60 = !DILocation(line: 0, scope: !55)
!61 = distinct !DISubprogram(name: "bpf.unit.2", linkageName: "bpf.unit.2", scope: null, file: !2, type: !62, flags: DIFlagArtificial, spFlags: DISPFlagDefinition, unit: !1, retainedNodes: !64)
!62 = !DISubroutineType(types: !63)
!63 = !{!9, !25, !10, !11, !10}
!64 = !{!65, !66, !67, !68}
!65 = !DILocalVariable(name: "ctx", arg: 1, scope: !61, file: !2, type: !25)
!66 = !DILocalVariable(name: "fiber", arg: 2, scope: !61, file: !2, type: !10)
!67 = !DILocalVariable(name: "fiber_control", arg: 3, scope: !61, file: !2, type: !11)
!68 = !DILocalVariable(name: "region", arg: 4, scope: !61, file: !2, type: !10)
!69 = !{i32 1}
!70 = !{i32 3}
!71 = !DILocation(line: 0, scope: !61)
!72 = distinct !DISubprogram(name: "__bpf_capsule_trampoline_step", linkageName: "__bpf_capsule_trampoline_step", scope: null, file: !2, type: !7, spFlags: DISPFlagDefinition, unit: !1, retainedNodes: !73)
!73 = !{!74, !75}
!74 = !DILocalVariable(name: "fiber", arg: 1, scope: !72, file: !2, type: !10)
!75 = !DILocalVariable(name: "fiber_control", arg: 2, scope: !72, file: !2, type: !11, annotations: !19)
!76 = !DILocation(line: 0, scope: !72)
!77 = distinct !DISubprogram(name: "bpf.dispatch.output.scalar.0", linkageName: "bpf.dispatch.output.scalar.0", scope: null, file: !2, type: !46, spFlags: DISPFlagDefinition, unit: !1, retainedNodes: !78)
!78 = !{!79, !80, !81}
!79 = !DILocalVariable(name: "fiber", arg: 1, scope: !77, file: !2, type: !10)
!80 = !DILocalVariable(name: "fiber_control", arg: 2, scope: !77, file: !2, type: !11, annotations: !19)
!81 = !DILocalVariable(name: "region", arg: 3, scope: !77, file: !2, type: !10)
!82 = !DILocation(line: 0, scope: !77)
!83 = distinct !DISubprogram(name: "__bpf_capsule_trampoline_ctx_step", linkageName: "__bpf_capsule_trampoline_ctx_step", scope: null, file: !2, type: !23, spFlags: DISPFlagDefinition, unit: !1, retainedNodes: !84)
!84 = !{!85, !86, !87}
!85 = !DILocalVariable(name: "ctx", arg: 1, scope: !83, file: !2, type: !25)
!86 = !DILocalVariable(name: "fiber", arg: 2, scope: !83, file: !2, type: !10)
!87 = !DILocalVariable(name: "fiber_control", arg: 3, scope: !83, file: !2, type: !11, annotations: !19)
!88 = !DILocation(line: 0, scope: !83)
!89 = distinct !DISubprogram(name: "bpf.dispatch.output.ctx.0", linkageName: "bpf.dispatch.output.ctx.0", scope: null, file: !2, type: !62, spFlags: DISPFlagDefinition, unit: !1, retainedNodes: !90)
!90 = !{!91, !92, !93, !94}
!91 = !DILocalVariable(name: "ctx", arg: 1, scope: !89, file: !2, type: !25)
!92 = !DILocalVariable(name: "fiber", arg: 2, scope: !89, file: !2, type: !10)
!93 = !DILocalVariable(name: "fiber_control", arg: 3, scope: !89, file: !2, type: !11, annotations: !19)
!94 = !DILocalVariable(name: "region", arg: 4, scope: !89, file: !2, type: !10)
!95 = !DILocation(line: 0, scope: !89)
