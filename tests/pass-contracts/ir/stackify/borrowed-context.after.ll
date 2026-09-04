source_filename = "stackify-borrowed-context.ll"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpfel"

%fiber_control = type { i32, i32, i64, i64, i64, i32, i32 }
%config = type { i32, i32, i32, i32, i32, i32, i32, i32, i32, i32, i32, i32, i64 }

@bpf_capsule_fibers = global [1 x %fiber_control] zeroinitializer, section ".bss.bpfctrl", align 8
@bpf_capsule_config = constant %config { i32 0, i32 4096, i32 0, i32 0, i32 1, i32 4096, i32 1, i32 0, i32 1, i32 0, i32 1112556353, i32 5, i64 0 }, section ".rodata.bpfconfig", align 4
@bpf_call_stack = internal global [262144 x i8] zeroinitializer, align 262144, !bpf.fiber.stack.size !0
@bpf_pc_unit = unnamed_addr constant [5 x i32] [i32 -1, i32 0, i32 1, i32 0, i32 0], section ".rodata.bpfpc", align 4

define i32 @__bpf_capsule_trampoline_ctx_l1(ptr %context, i32 %fiber, ptr %control) #0 !dbg !6 {
entry:
  %status = call i32 @__bpf_capsule_trampoline_ctx_step(ptr %context, i32 %fiber, ptr %control), !dbg !22
  ret i32 %status, !dbg !22
}

define i32 @__bpf_capsule_trampoline_ctx(ptr %context, i32 %fiber) #0 {
entry:
  %control = getelementptr [1 x %fiber_control], ptr @bpf_capsule_fibers, i32 0, i32 %fiber
  %status = call i32 @__bpf_capsule_trampoline_ctx_l1(ptr %context, i32 %fiber, ptr %control)
  ret i32 %status
}

define i32 @start(ptr %context, i32 %fiber) section "xdp" !dbg !23 !bpf.native !26 {
entry:
  %fiber.index = and i32 %fiber, 0
  %fiber.index1 = and i32 %fiber.index, 0
  %0 = zext i32 %fiber.index1 to i64
  %1 = mul i64 %0, 262144
  %stack.linear.offset = add i64 %1, 262112
  %fiber.stack = getelementptr i8, ptr @bpf_call_stack, i64 %stack.linear.offset
  %root.fp = ptrtoint ptr %fiber.stack to i64
  %fiber.index2 = and i32 %fiber.index, 0
  %fiber.control = getelementptr inbounds [1 x %fiber_control], ptr @bpf_capsule_fibers, i32 0, i32 %fiber.index2, !bpf.capsule.sectioned.bounded !26
  %fiber.outcome = getelementptr inbounds nuw %fiber_control, ptr %fiber.control, i32 0, i32 0
  store i64 0, ptr %fiber.outcome, align 8
  %root.saved.fp = getelementptr i8, ptr %fiber.stack, i64 0
  store i64 0, ptr %root.saved.fp, align 8
  %root.return.pc = getelementptr i8, ptr %fiber.stack, i64 8
  store i32 -1, ptr %root.return.pc, align 4
  %fiber.index3 = and i32 %fiber.index, 0
  %fiber.control4 = getelementptr inbounds [1 x %fiber_control], ptr @bpf_capsule_fibers, i32 0, i32 %fiber.index3, !bpf.capsule.sectioned.bounded !26
  %fiber.return.size = getelementptr inbounds nuw %fiber_control, ptr %fiber.control4, i32 0, i32 6
  store i32 4, ptr %fiber.return.size, align 4
  %fiber.index5 = and i32 %fiber.index, 0
  %fiber.control6 = getelementptr inbounds [1 x %fiber_control], ptr @bpf_capsule_fibers, i32 0, i32 %fiber.index5, !bpf.capsule.sectioned.bounded !26
  %fiber.pc = getelementptr inbounds nuw %fiber_control, ptr %fiber.control6, i32 0, i32 5
  store i32 1, ptr %fiber.pc, align 4
  %fiber.index7 = and i32 %fiber.index, 0
  %fiber.control8 = getelementptr inbounds [1 x %fiber_control], ptr @bpf_capsule_fibers, i32 0, i32 %fiber.index7, !bpf.capsule.sectioned.bounded !26
  %fiber.sp = getelementptr inbounds nuw %fiber_control, ptr %fiber.control8, i32 0, i32 3
  store i64 %root.fp, ptr %fiber.sp, align 8
  %fiber.index9 = and i32 %fiber.index, 0
  %fiber.control10 = getelementptr inbounds [1 x %fiber_control], ptr @bpf_capsule_fibers, i32 0, i32 %fiber.index9, !bpf.capsule.sectioned.bounded !26
  %fiber.fp = getelementptr inbounds nuw %fiber_control, ptr %fiber.control10, i32 0, i32 4
  store i64 %root.fp, ptr %fiber.fp, align 8
  %control.i = getelementptr [1 x %fiber_control], ptr @bpf_capsule_fibers, i32 0, i32 %fiber.index
  %status.i = call i32 @__bpf_capsule_trampoline_ctx_l1(ptr %context, i32 %fiber.index, ptr %control.i), !dbg !27
  %fiber.index11 = and i32 %fiber.index, 0
  %2 = zext i32 %fiber.index11 to i64
  %3 = mul i64 %2, 262144
  %stack.linear.offset12 = add i64 %3, 262128
  %fiber.stack13 = getelementptr i8, ptr @bpf_call_stack, i64 %stack.linear.offset12
  %root.result = load i32, ptr %fiber.stack13, align 8
  ret i32 %root.result
}

; Function Attrs: noinline
define i32 @bpf_capsule_set_outcome(i32 %fiber, i64 %outcome) #1 !dbg !28 !bpf.native.scalar !26 {
entry:
  %fiber.index = and i32 %fiber, 0, !dbg !35
  %fiber.control = getelementptr inbounds [1 x %fiber_control], ptr @bpf_capsule_fibers, i32 0, i32 %fiber.index, !dbg !35, !bpf.capsule.sectioned.bounded !26
  %fiber.outcome = getelementptr inbounds nuw %fiber_control, ptr %fiber.control, i32 0, i32 0, !dbg !35
  store volatile i64 %outcome, ptr %fiber.outcome, align 8, !dbg !35
  ret i32 0, !dbg !35
}

; Function Attrs: noinline
define i32 @__bpf_capsule_trampoline_step(i32 %fiber, ptr "bpf.capsule.control" %fiber_control) #2 !dbg !36 !bpf.capsule !26 !bpf.capsule.allocation.unit !42 !bpf.capsule.stack.size !0 {
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
  %fiber.fp = getelementptr inbounds nuw %fiber_control, ptr %fiber_control, i32 0, i32 4, !dbg !43
  %frame.fp = load i64, ptr %fiber.fp, align 8, !dbg !43
  %frame.addr = inttoptr i64 %frame.fp to ptr, !dbg !43
  %fiber.index = and i32 %fiber, 0, !dbg !43
  %7 = zext i32 %fiber.index to i64, !dbg !43
  %8 = mul i64 %7, 262144, !dbg !43
  %stack.linear.offset = add i64 %8, 0, !dbg !43
  %fiber.stack = getelementptr i8, ptr @bpf_call_stack, i64 %stack.linear.offset, !dbg !43
  call void asm sideeffect "# bpf_capsule_stack_anchor", "r"(ptr %fiber.stack), !dbg !43
  %fiber.pc4 = getelementptr inbounds nuw %fiber_control, ptr %fiber_control, i32 0, i32 5, !dbg !43
  %pc5 = load i32, ptr %fiber.pc4, align 4, !dbg !43
  %9 = icmp ult i32 %pc5, 3, !dbg !43
  br i1 %9, label %unit.test.left, label %unit.test.right, !dbg !43

unit.control.missing:                             ; preds = %unit.entry
  ret i32 1

borrowed_root.prologue:                           ; preds = %unit.test.left
  %frame.sp = sub i64 %frame.fp, 0
  %slice.offset = and i64 %frame.fp, 262143
  %10 = icmp ult i64 %slice.offset, 131104
  br i1 %10, label %borrowed_root.prologue.overflow, label %entry

entry:                                            ; preds = %borrowed_root.prologue
  %fiber.sp = getelementptr inbounds nuw %fiber_control, ptr %fiber_control, i32 0, i32 3
  store i64 %frame.sp, ptr %fiber.sp, align 8
  %caller.sp = sub i64 %frame.fp, 0
  %callee.fp = sub i64 %caller.sp, 32
  %callee.frame = getelementptr i8, ptr %frame.addr, i64 -32
  %saved.fp.slot = getelementptr i8, ptr %callee.frame, i64 0
  store i64 %frame.fp, ptr %saved.fp.slot, align 8
  %return.pc.slot = getelementptr i8, ptr %callee.frame, i64 8
  store i32 3, ptr %return.pc.slot, align 4
  %11 = getelementptr i8, ptr %callee.frame, i64 24
  store i32 5, ptr %11, align 8
  %fiber.pc3 = getelementptr inbounds nuw %fiber_control, ptr %fiber_control, i32 0, i32 5
  store i32 2, ptr %fiber.pc3, align 4
  %fiber.fp4 = getelementptr inbounds nuw %fiber_control, ptr %fiber_control, i32 0, i32 4
  store i64 %callee.fp, ptr %fiber.fp4, align 8
  ret i32 0

borrowed_root.prologue.overflow:                  ; preds = %borrowed_root.prologue
  %fiber.outcome = getelementptr inbounds nuw %fiber_control, ptr %fiber_control, i32 0, i32 0
  %12 = call i32 @bpf_capsule_set_outcome(i32 %fiber, i64 -30064771069), !dbg !43
  ret i32 0

entry.resume:                                     ; preds = %unit.test.left6
  %returned.frame = getelementptr i8, ptr %frame.addr, i64 -32
  %result.slot5 = getelementptr i8, ptr %returned.frame, i64 16
  %callret = load i32, ptr %result.slot5, align 8
  %caller.sp6 = sub i64 %frame.fp, 0
  %callee.fp7 = sub i64 %caller.sp6, 32
  %callee.frame8 = getelementptr i8, ptr %frame.addr, i64 -32
  %saved.fp.slot9 = getelementptr i8, ptr %callee.frame8, i64 0
  store i64 %frame.fp, ptr %saved.fp.slot9, align 8
  %return.pc.slot10 = getelementptr i8, ptr %callee.frame8, i64 8
  store i32 4, ptr %return.pc.slot10, align 4
  %13 = getelementptr i8, ptr %callee.frame8, i64 24
  store i32 %callret, ptr %13, align 8
  %fiber.pc11 = getelementptr inbounds nuw %fiber_control, ptr %fiber_control, i32 0, i32 5
  store i32 2, ptr %fiber.pc11, align 4
  %fiber.fp12 = getelementptr inbounds nuw %fiber_control, ptr %fiber_control, i32 0, i32 4
  store i64 %callee.fp7, ptr %fiber.fp12, align 8
  ret i32 0

entry.resume.resume:                              ; preds = %unit.test.right7
  %returned.frame13 = getelementptr i8, ptr %frame.addr, i64 -32
  %result.slot14 = getelementptr i8, ptr %returned.frame13, i64 16
  %callret15 = load i32, ptr %result.slot14, align 8
  %result.slot = getelementptr i8, ptr %frame.addr, i64 16
  store i32 %callret15, ptr %result.slot, align 8
  %14 = getelementptr i8, ptr %frame.addr, i64 8
  %return.pc = load i32, ptr %14, align 4
  %15 = getelementptr i8, ptr %frame.addr, i64 0
  %saved.fp = load i64, ptr %15, align 8
  %fiber.pc = getelementptr inbounds nuw %fiber_control, ptr %fiber_control, i32 0, i32 5
  store i32 %return.pc, ptr %fiber.pc, align 4
  %return.sp = add i64 %frame.fp, 16
  %fiber.sp1 = getelementptr inbounds nuw %fiber_control, ptr %fiber_control, i32 0, i32 3
  store i64 %return.sp, ptr %fiber.sp1, align 8
  %fiber.fp2 = getelementptr inbounds nuw %fiber_control, ptr %fiber_control, i32 0, i32 4
  store i64 %saved.fp, ptr %fiber.fp2, align 8
  ret i32 0

unit.test.left:                                   ; preds = %unit.control.ready
  %16 = icmp eq i32 %pc5, 1
  br i1 %16, label %borrowed_root.prologue, label %unit.unknown

unit.test.right:                                  ; preds = %unit.control.ready
  %17 = icmp ult i32 %pc5, 4
  br i1 %17, label %unit.test.left6, label %unit.test.right7

unit.test.left6:                                  ; preds = %unit.test.right
  %18 = icmp eq i32 %pc5, 3
  br i1 %18, label %entry.resume, label %unit.unknown

unit.test.right7:                                 ; preds = %unit.test.right
  %19 = icmp eq i32 %pc5, 4
  br i1 %19, label %entry.resume.resume, label %unit.unknown

unit.unknown:                                     ; preds = %unit.test.right7, %unit.test.left6, %unit.test.left
  %20 = call i32 @bpf_capsule_set_outcome(i32 %fiber, i64 -38654705661), !dbg !43
  ret i32 0, !dbg !43
}

; Function Attrs: noinline
define i32 @bpf.unit.1(ptr "bpf.capsule.borrowed" %ctx, i32 %fiber, ptr "bpf.capsule.control" %fiber_control) #1 !dbg !44 !bpf.capsule !26 !bpf.capsule.allocation.unit !49 !bpf.capsule.stack.size !0 !bpf.capsule.flatten.unit !50 {
unit.entry:
  %fiber.fp = getelementptr inbounds nuw %fiber_control, ptr %fiber_control, i32 0, i32 4, !dbg !51
  %frame.fp = load i64, ptr %fiber.fp, align 8, !dbg !51
  %frame.addr = inttoptr i64 %frame.fp to ptr, !dbg !51
  %fiber.index = and i32 %fiber, 0, !dbg !51
  %0 = zext i32 %fiber.index to i64, !dbg !51
  %1 = mul i64 %0, 262144, !dbg !51
  %stack.linear.offset = add i64 %1, 0, !dbg !51
  %fiber.stack = getelementptr i8, ptr @bpf_call_stack, i64 %stack.linear.offset, !dbg !51
  call void asm sideeffect "# bpf_capsule_stack_anchor", "r"(ptr %fiber.stack), !dbg !51
  %fiber.pc1 = getelementptr inbounds nuw %fiber_control, ptr %fiber_control, i32 0, i32 5, !dbg !51
  %pc = load i32, ptr %fiber.pc1, align 4, !dbg !51
  br label %context_helper.prologue, !dbg !51

context_helper.prologue:                          ; preds = %unit.entry
  %frame.sp = sub i64 %frame.fp, 0
  %slice.offset = and i64 %frame.fp, 262143
  %2 = icmp ult i64 %slice.offset, 131104
  br i1 %2, label %context_helper.prologue.overflow, label %entry

entry:                                            ; preds = %context_helper.prologue
  %fiber.sp = getelementptr inbounds nuw %fiber_control, ptr %fiber_control, i32 0, i32 3
  store i64 %frame.sp, ptr %fiber.sp, align 8
  call void asm sideeffect "", "r"(ptr %ctx), !dbg !51
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

context_helper.prologue.overflow:                 ; preds = %context_helper.prologue
  %fiber.outcome = getelementptr inbounds nuw %fiber_control, ptr %fiber_control, i32 0, i32 0
  %6 = call i32 @bpf_capsule_set_outcome(i32 %fiber, i64 -30064771069), !dbg !51
  ret i32 0
}

; Function Attrs: noinline
define i32 @__bpf_capsule_trampoline_ctx_step(ptr "bpf.capsule.borrowed" %ctx, i32 %fiber, ptr "bpf.capsule.control" %fiber_control) #2 !dbg !52 {
entry:
  %0 = icmp ne ptr %fiber_control, null, !dbg !57
  br i1 %0, label %control.ready, label %control.missing, !dbg !57

iterate:                                          ; preds = %control.ready
  %fiber.pc = getelementptr inbounds nuw %fiber_control, ptr %fiber_control, i32 0, i32 5, !dbg !57
  %pc = load i32, ptr %fiber.pc, align 4, !dbg !57
  %1 = icmp eq i32 %pc, -1, !dbg !57
  %fiber.outcome = getelementptr inbounds nuw %fiber_control, ptr %fiber_control, i32 0, i32 0, !dbg !57
  %2 = load i64, ptr %fiber.outcome, align 8, !dbg !57
  %3 = icmp ne i64 %2, 0, !dbg !57
  %4 = icmp eq i32 %pc, 0, !dbg !57
  %5 = or i1 %1, %3, !dbg !57
  %6 = or i1 %4, %5, !dbg !57
  br i1 %6, label %terminal, label %route, !dbg !57

control.ready:                                    ; preds = %entry
  br label %iterate, !dbg !57

control.missing:                                  ; preds = %entry
  ret i32 1, !dbg !57

route:                                            ; preds = %iterate
  br label %route.lookup, !dbg !57

route.lookup:                                     ; preds = %route
  %7 = icmp ult i32 %pc, 5, !dbg !57
  br i1 %7, label %route.pc.ready, label %bad.id, !dbg !57

route.pc.ready:                                   ; preds = %route.lookup
  %8 = zext i32 %pc to i64, !dbg !57
  %9 = getelementptr inbounds [5 x i32], ptr @bpf_pc_unit, i64 0, i64 %8, !dbg !57
  %allocation.unit = load i32, ptr %9, align 4, !dbg !57
  br label %dispatch, !dbg !57

dispatch:                                         ; preds = %route.pc.ready
  switch i32 %allocation.unit, label %bad.id [
    i32 0, label %scalar.step
    i32 1, label %bpf.dispatch.output.ctx.0
  ], !dbg !57

bpf.dispatch.output.ctx.0:                        ; preds = %dispatch
  %10 = call i32 @bpf.dispatch.output.ctx.0(ptr %ctx, i32 %fiber, ptr %fiber_control, i32 %allocation.unit), !dbg !57
  ret i32 %10, !dbg !57

terminal:                                         ; preds = %iterate
  br i1 %1, label %completed, label %done, !dbg !57

completed:                                        ; preds = %terminal
  store i32 0, ptr %fiber.pc, align 4, !dbg !57
  br label %done, !dbg !57

scalar.step:                                      ; preds = %dispatch
  %11 = call i32 @__bpf_capsule_trampoline_step(i32 %fiber, ptr %fiber_control), !dbg !57
  ret i32 %11, !dbg !57

done:                                             ; preds = %completed, %terminal
  ret i32 1, !dbg !57

bad.id:                                           ; preds = %dispatch, %route.lookup
  %12 = call i32 @bpf_capsule_set_outcome(i32 %fiber, i64 -38654705661), !dbg !57
  ret i32 1, !dbg !57
}

; Function Attrs: noinline
define i32 @bpf.dispatch.output.ctx.0(ptr "bpf.capsule.borrowed" %ctx, i32 %fiber, ptr "bpf.capsule.control" %fiber_control, i32 %dispatch_key) #1 !dbg !58 !bpf.capsule.flatten.root !50 {
entry:
  %0 = icmp ne ptr %fiber_control, null, !dbg !66
  br i1 %0, label %dispatch, label %bad.id, !dbg !66

dispatch:                                         ; preds = %entry
  switch i32 %dispatch_key, label %bad.id [
    i32 1, label %bpf.unit.1
  ], !dbg !66

bad.id:                                           ; preds = %dispatch, %entry
  %1 = call i32 @bpf_capsule_set_outcome(i32 %fiber, i64 -38654705661), !dbg !66
  ret i32 1, !dbg !66

bpf.unit.1:                                       ; preds = %dispatch
  %2 = call i32 @bpf.unit.1(ptr %ctx, i32 %fiber, ptr %fiber_control), !dbg !66
  ret i32 %2, !dbg !66
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
!6 = distinct !DISubprogram(name: "__bpf_capsule_trampoline_ctx_l1", linkageName: "__bpf_capsule_trampoline_ctx_l1", scope: null, file: !2, type: !7, spFlags: DISPFlagDefinition, unit: !1, retainedNodes: !18)
!7 = !DISubroutineType(types: !8)
!8 = !{!9, !10, !12, !13}
!9 = !DIBasicType(name: "int", size: 32, encoding: DW_ATE_signed)
!10 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !11, size: 64)
!11 = distinct !DICompositeType(tag: DW_TAG_structure_type, name: "xdp_md", file: !2, size: 192)
!12 = !DIBasicType(name: "unsigned int", size: 32, encoding: DW_ATE_unsigned)
!13 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !14, size: 64)
!14 = !DICompositeType(tag: DW_TAG_array_type, baseType: !15, size: 320, align: 8, elements: !16)
!15 = !DIBasicType(name: "unsigned char", size: 8, encoding: DW_ATE_unsigned_char)
!16 = !{!17}
!17 = !DISubrange(count: 40, lowerBound: 0)
!18 = !{!19, !20, !21}
!19 = !DILocalVariable(name: "context", arg: 1, scope: !6, file: !2, type: !10)
!20 = !DILocalVariable(name: "fiber", arg: 2, scope: !6, file: !2, type: !12)
!21 = !DILocalVariable(name: "control", arg: 3, scope: !6, file: !2, type: !13)
!22 = !DILocation(line: 0, scope: !6)
!23 = distinct !DISubprogram(name: "start", scope: !2, file: !2, type: !24, spFlags: DISPFlagDefinition, unit: !1)
!24 = !DISubroutineType(types: !25)
!25 = !{!9, !10, !9}
!26 = !{}
!27 = !DILocation(line: 0, scope: !23)
!28 = distinct !DISubprogram(name: "bpf_capsule_set_outcome", linkageName: "bpf_capsule_set_outcome", scope: null, file: !2, type: !29, spFlags: DISPFlagDefinition, unit: !1, retainedNodes: !32)
!29 = !DISubroutineType(types: !30)
!30 = !{!9, !9, !31}
!31 = !DIBasicType(name: "long long", size: 64, encoding: DW_ATE_signed)
!32 = !{!33, !34}
!33 = !DILocalVariable(name: "a0", arg: 1, scope: !28, file: !2, type: !9)
!34 = !DILocalVariable(name: "a1", arg: 2, scope: !28, file: !2, type: !31)
!35 = !DILocation(line: 0, scope: !28)
!36 = distinct !DISubprogram(name: "__bpf_capsule_trampoline_step", linkageName: "__bpf_capsule_trampoline_step", scope: null, file: !2, type: !37, flags: DIFlagArtificial, spFlags: DISPFlagDefinition, unit: !1, retainedNodes: !39)
!37 = !DISubroutineType(types: !38)
!38 = !{!9, !12, !13}
!39 = !{!40, !41}
!40 = !DILocalVariable(name: "fiber", arg: 1, scope: !36, file: !2, type: !12)
!41 = !DILocalVariable(name: "fiber_control", arg: 2, scope: !36, file: !2, type: !13)
!42 = !{i32 0}
!43 = !DILocation(line: 0, scope: !36)
!44 = distinct !DISubprogram(name: "bpf.unit.1", linkageName: "bpf.unit.1", scope: null, file: !2, type: !7, flags: DIFlagArtificial, spFlags: DISPFlagDefinition, unit: !1, retainedNodes: !45)
!45 = !{!46, !47, !48}
!46 = !DILocalVariable(name: "ctx", arg: 1, scope: !44, file: !2, type: !10)
!47 = !DILocalVariable(name: "fiber", arg: 2, scope: !44, file: !2, type: !12)
!48 = !DILocalVariable(name: "fiber_control", arg: 3, scope: !44, file: !2, type: !13)
!49 = !{i32 1}
!50 = !{i32 2}
!51 = !DILocation(line: 0, scope: !44)
!52 = distinct !DISubprogram(name: "__bpf_capsule_trampoline_ctx_step", linkageName: "__bpf_capsule_trampoline_ctx_step", scope: null, file: !2, type: !7, spFlags: DISPFlagDefinition, unit: !1, retainedNodes: !53)
!53 = !{!54, !55, !56}
!54 = !DILocalVariable(name: "ctx", arg: 1, scope: !52, file: !2, type: !10)
!55 = !DILocalVariable(name: "fiber", arg: 2, scope: !52, file: !2, type: !12)
!56 = !DILocalVariable(name: "fiber_control", arg: 3, scope: !52, file: !2, type: !13)
!57 = !DILocation(line: 0, scope: !52)
!58 = distinct !DISubprogram(name: "bpf.dispatch.output.ctx.0", linkageName: "bpf.dispatch.output.ctx.0", scope: null, file: !2, type: !59, spFlags: DISPFlagDefinition, unit: !1, retainedNodes: !61)
!59 = !DISubroutineType(types: !60)
!60 = !{!9, !10, !12, !13, !12}
!61 = !{!62, !63, !64, !65}
!62 = !DILocalVariable(name: "ctx", arg: 1, scope: !58, file: !2, type: !10)
!63 = !DILocalVariable(name: "fiber", arg: 2, scope: !58, file: !2, type: !12)
!64 = !DILocalVariable(name: "fiber_control", arg: 3, scope: !58, file: !2, type: !13)
!65 = !DILocalVariable(name: "dispatch_key", arg: 4, scope: !58, file: !2, type: !12)
!66 = !DILocation(line: 0, scope: !58)
