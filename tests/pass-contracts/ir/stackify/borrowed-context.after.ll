source_filename = "stackify-borrowed-context.ll"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpfel"

%fiber_control = type { i32, i32, i64, i64, i64, i32, i32 }
%config = type { i32, i32, i32, i32, i32, i32, i32, i32, i32, i32, i32, i32, i64 }

@bpf_capsule_fibers = global [1 x %fiber_control] zeroinitializer, section ".bss.bpfctrl", align 8
@bpf_capsule_config = constant %config { i32 0, i32 4096, i32 0, i32 0, i32 1, i32 4096, i32 1, i32 0, i32 1, i32 0, i32 1112556353, i32 5, i64 0 }, section ".rodata.bpfconfig", align 4
@bpf_call_stack = internal global [262144 x i8] zeroinitializer, align 262144, !bpf.fiber.stack.size !0
@bpf_pc_unit = unnamed_addr constant [5 x i32] [i32 -1, i32 0, i32 1, i32 0, i32 0], section ".rodata.bpfpc", align 4

define i32 @__bpf_capsule_trampoline_ctx_l1(ptr %context, i32 %fiber, ptr %control) #0 {
entry:
  %status = call i32 @__bpf_capsule_trampoline_ctx_step(ptr %context, i32 %fiber, ptr %control)
  ret i32 %status
}

define i32 @__bpf_capsule_trampoline_ctx(ptr %context, i32 %fiber) #0 {
entry:
  %control = getelementptr [1 x %fiber_control], ptr @bpf_capsule_fibers, i32 0, i32 %fiber
  %status = call i32 @__bpf_capsule_trampoline_ctx_l1(ptr %context, i32 %fiber, ptr %control)
  ret i32 %status
}

define i32 @start(ptr %context, i32 %fiber) section "xdp" !dbg !6 !bpf.native !12 {
entry:
  %fiber.index = and i32 %fiber, 0
  %fiber.index1 = and i32 %fiber.index, 0
  %0 = zext i32 %fiber.index1 to i64
  %1 = mul i64 %0, 262144
  %stack.linear.offset = add i64 %1, 262128
  %fiber.stack = getelementptr i8, ptr @bpf_call_stack, i64 %stack.linear.offset
  %root.fp = ptrtoint ptr %fiber.stack to i64
  %fiber.index2 = and i32 %fiber.index, 0
  %fiber.control = getelementptr inbounds [1 x %fiber_control], ptr @bpf_capsule_fibers, i32 0, i32 %fiber.index2, !bpf.capsule.sectioned.bounded !12
  %fiber.outcome = getelementptr inbounds nuw %fiber_control, ptr %fiber.control, i32 0, i32 0
  store i64 0, ptr %fiber.outcome, align 8
  %root.return.pc = getelementptr i8, ptr %fiber.stack, i64 -8
  store i32 -1, ptr %root.return.pc, align 4
  %root.saved.fp = getelementptr i8, ptr %fiber.stack, i64 -16
  store i64 0, ptr %root.saved.fp, align 8
  %fiber.index3 = and i32 %fiber.index, 0
  %fiber.control4 = getelementptr inbounds [1 x %fiber_control], ptr @bpf_capsule_fibers, i32 0, i32 %fiber.index3, !bpf.capsule.sectioned.bounded !12
  %fiber.return.size = getelementptr inbounds nuw %fiber_control, ptr %fiber.control4, i32 0, i32 6
  store i32 4, ptr %fiber.return.size, align 4
  %fiber.index5 = and i32 %fiber.index, 0
  %fiber.control6 = getelementptr inbounds [1 x %fiber_control], ptr @bpf_capsule_fibers, i32 0, i32 %fiber.index5, !bpf.capsule.sectioned.bounded !12
  %fiber.pc = getelementptr inbounds nuw %fiber_control, ptr %fiber.control6, i32 0, i32 5
  store i32 1, ptr %fiber.pc, align 4
  %fiber.index7 = and i32 %fiber.index, 0
  %fiber.control8 = getelementptr inbounds [1 x %fiber_control], ptr @bpf_capsule_fibers, i32 0, i32 %fiber.index7, !bpf.capsule.sectioned.bounded !12
  %fiber.sp = getelementptr inbounds nuw %fiber_control, ptr %fiber.control8, i32 0, i32 3
  store i64 %root.fp, ptr %fiber.sp, align 8
  %fiber.index9 = and i32 %fiber.index, 0
  %fiber.control10 = getelementptr inbounds [1 x %fiber_control], ptr @bpf_capsule_fibers, i32 0, i32 %fiber.index9, !bpf.capsule.sectioned.bounded !12
  %fiber.fp = getelementptr inbounds nuw %fiber_control, ptr %fiber.control10, i32 0, i32 4
  store i64 %root.fp, ptr %fiber.fp, align 8
  %control.i = getelementptr [1 x %fiber_control], ptr @bpf_capsule_fibers, i32 0, i32 %fiber.index
  %status.i = call i32 @__bpf_capsule_trampoline_ctx_l1(ptr %context, i32 %fiber.index, ptr %control.i), !dbg !13
  %fiber.index11 = and i32 %fiber.index, 0
  %2 = zext i32 %fiber.index11 to i64
  %3 = mul i64 %2, 262144
  %stack.linear.offset12 = add i64 %3, 262128
  %fiber.stack13 = getelementptr i8, ptr @bpf_call_stack, i64 %stack.linear.offset12
  %root.result = load i32, ptr %fiber.stack13, align 4
  ret i32 %root.result
}

; Function Attrs: noinline
define i32 @bpf_capsule_set_outcome(i32 %fiber, i64 %outcome) #1 !dbg !14 !bpf.native.scalar !12 {
entry:
  %fiber.index = and i32 %fiber, 0, !dbg !21
  %fiber.control = getelementptr inbounds [1 x %fiber_control], ptr @bpf_capsule_fibers, i32 0, i32 %fiber.index, !dbg !21, !bpf.capsule.sectioned.bounded !12
  %fiber.outcome = getelementptr inbounds nuw %fiber_control, ptr %fiber.control, i32 0, i32 0, !dbg !21
  store volatile i64 %outcome, ptr %fiber.outcome, align 8, !dbg !21
  ret i32 0, !dbg !21
}

; Function Attrs: noinline
define i32 @__bpf_capsule_trampoline_step(i32 %fiber, ptr "bpf.capsule.control" %fiber_control) #2 !dbg !22 !bpf.capsule !12 !bpf.capsule.allocation.unit !34 !bpf.capsule.stack.size !0 {
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
  %fiber.fp = getelementptr inbounds nuw %fiber_control, ptr %fiber_control, i32 0, i32 4, !dbg !35
  %frame.fp = load i64, ptr %fiber.fp, align 8, !dbg !35
  %frame.addr = inttoptr i64 %frame.fp to ptr, !dbg !35
  %fiber.index = and i32 %fiber, 0, !dbg !35
  %7 = zext i32 %fiber.index to i64, !dbg !35
  %8 = mul i64 %7, 262144, !dbg !35
  %stack.linear.offset = add i64 %8, 0, !dbg !35
  %fiber.stack = getelementptr i8, ptr @bpf_call_stack, i64 %stack.linear.offset, !dbg !35
  call void asm sideeffect "# bpf_capsule_stack_anchor", "r"(ptr %fiber.stack), !dbg !35
  %fiber.pc4 = getelementptr inbounds nuw %fiber_control, ptr %fiber_control, i32 0, i32 5, !dbg !35
  %pc5 = load i32, ptr %fiber.pc4, align 4, !dbg !35
  %9 = icmp ult i32 %pc5, 3, !dbg !35
  br i1 %9, label %unit.test.left, label %unit.test.right, !dbg !35

unit.control.missing:                             ; preds = %unit.entry
  ret i32 1

borrowed_root.prologue:                           ; preds = %unit.test.left
  %frame.sp = sub i64 %frame.fp, 32
  %slice.offset = and i64 %frame.fp, 262143
  %10 = icmp ult i64 %slice.offset, 131136
  br i1 %10, label %borrowed_root.prologue.overflow, label %entry

entry:                                            ; preds = %borrowed_root.prologue
  %fiber.sp = getelementptr inbounds nuw %fiber_control, ptr %fiber_control, i32 0, i32 3
  store i64 %frame.sp, ptr %fiber.sp, align 8
  %callee.fp = sub i64 %frame.fp, 32
  %return.pc.slot = getelementptr i8, ptr %frame.addr, i64 -40
  store i32 3, ptr %return.pc.slot, align 4
  %saved.fp.slot = getelementptr i8, ptr %frame.addr, i64 -48
  store i64 %frame.fp, ptr %saved.fp.slot, align 8
  %11 = getelementptr i8, ptr %frame.addr, i64 -56
  store i32 5, ptr %11, align 4
  %fiber.pc3 = getelementptr inbounds nuw %fiber_control, ptr %fiber_control, i32 0, i32 5
  store i32 2, ptr %fiber.pc3, align 4
  %fiber.fp4 = getelementptr inbounds nuw %fiber_control, ptr %fiber_control, i32 0, i32 4
  store i64 %callee.fp, ptr %fiber.fp4, align 8
  ret i32 0

borrowed_root.prologue.overflow:                  ; preds = %borrowed_root.prologue
  %fiber.outcome = getelementptr inbounds nuw %fiber_control, ptr %fiber_control, i32 0, i32 0
  %12 = call i32 @bpf_capsule_set_outcome(i32 %fiber, i64 -30064771069), !dbg !35
  ret i32 0

entry.resume:                                     ; preds = %unit.test.left6
  %result.zone = getelementptr i8, ptr %frame.addr, i64 -32
  %callret = load i32, ptr %result.zone, align 4
  %callee.fp5 = sub i64 %frame.fp, 32
  %return.pc.slot6 = getelementptr i8, ptr %frame.addr, i64 -40
  store i32 4, ptr %return.pc.slot6, align 4
  %saved.fp.slot7 = getelementptr i8, ptr %frame.addr, i64 -48
  store i64 %frame.fp, ptr %saved.fp.slot7, align 8
  %13 = getelementptr i8, ptr %frame.addr, i64 -56
  store i32 %callret, ptr %13, align 4
  %fiber.pc8 = getelementptr inbounds nuw %fiber_control, ptr %fiber_control, i32 0, i32 5
  store i32 2, ptr %fiber.pc8, align 4
  %fiber.fp9 = getelementptr inbounds nuw %fiber_control, ptr %fiber_control, i32 0, i32 4
  store i64 %callee.fp5, ptr %fiber.fp9, align 8
  ret i32 0

entry.resume.resume:                              ; preds = %unit.test.right7
  %result.zone10 = getelementptr i8, ptr %frame.addr, i64 -32
  %callret11 = load i32, ptr %result.zone10, align 4
  store i32 %callret11, ptr %frame.addr, align 4
  %14 = getelementptr i8, ptr %frame.addr, i64 -8
  %return.pc = load i32, ptr %14, align 4
  %15 = getelementptr i8, ptr %frame.addr, i64 -16
  %saved.fp = load i64, ptr %15, align 8
  %fiber.pc = getelementptr inbounds nuw %fiber_control, ptr %fiber_control, i32 0, i32 5
  store i32 %return.pc, ptr %fiber.pc, align 4
  %fiber.sp1 = getelementptr inbounds nuw %fiber_control, ptr %fiber_control, i32 0, i32 3
  store i64 %frame.fp, ptr %fiber.sp1, align 8
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
  %20 = call i32 @bpf_capsule_set_outcome(i32 %fiber, i64 -38654705661), !dbg !35
  ret i32 0, !dbg !35
}

; Function Attrs: noinline
define i32 @bpf.unit.1(ptr "bpf.capsule.borrowed" %ctx, i32 %fiber, ptr "bpf.capsule.control" %fiber_control) #1 !dbg !36 !bpf.capsule !12 !bpf.capsule.allocation.unit !43 !bpf.capsule.stack.size !0 !bpf.capsule.flatten.unit !44 {
unit.entry:
  %fiber.fp = getelementptr inbounds nuw %fiber_control, ptr %fiber_control, i32 0, i32 4, !dbg !45
  %frame.fp = load i64, ptr %fiber.fp, align 8, !dbg !45
  %frame.addr = inttoptr i64 %frame.fp to ptr, !dbg !45
  %fiber.index = and i32 %fiber, 0, !dbg !45
  %0 = zext i32 %fiber.index to i64, !dbg !45
  %1 = mul i64 %0, 262144, !dbg !45
  %stack.linear.offset = add i64 %1, 0, !dbg !45
  %fiber.stack = getelementptr i8, ptr @bpf_call_stack, i64 %stack.linear.offset, !dbg !45
  call void asm sideeffect "# bpf_capsule_stack_anchor", "r"(ptr %fiber.stack), !dbg !45
  %fiber.pc1 = getelementptr inbounds nuw %fiber_control, ptr %fiber_control, i32 0, i32 5, !dbg !45
  %pc = load i32, ptr %fiber.pc1, align 4, !dbg !45
  br label %context_helper.prologue, !dbg !45

context_helper.prologue:                          ; preds = %unit.entry
  %frame.sp = sub i64 %frame.fp, 32
  %slice.offset = and i64 %frame.fp, 262143
  %2 = icmp ult i64 %slice.offset, 131136
  br i1 %2, label %context_helper.prologue.overflow, label %entry

entry:                                            ; preds = %context_helper.prologue
  %fiber.sp = getelementptr inbounds nuw %fiber_control, ptr %fiber_control, i32 0, i32 3
  store i64 %frame.sp, ptr %fiber.sp, align 8
  call void asm sideeffect "", "r"(ptr %ctx), !dbg !45
  %3 = getelementptr i8, ptr %frame.addr, i64 -24
  %value = load i32, ptr %3, align 4
  %result = add i32 %value, 1
  store i32 %result, ptr %frame.addr, align 4
  %4 = getelementptr i8, ptr %frame.addr, i64 -8
  %return.pc = load i32, ptr %4, align 4
  %5 = getelementptr i8, ptr %frame.addr, i64 -16
  %saved.fp = load i64, ptr %5, align 8
  %fiber.pc = getelementptr inbounds nuw %fiber_control, ptr %fiber_control, i32 0, i32 5
  store i32 %return.pc, ptr %fiber.pc, align 4
  %fiber.sp1 = getelementptr inbounds nuw %fiber_control, ptr %fiber_control, i32 0, i32 3
  store i64 %frame.fp, ptr %fiber.sp1, align 8
  %fiber.fp2 = getelementptr inbounds nuw %fiber_control, ptr %fiber_control, i32 0, i32 4
  store i64 %saved.fp, ptr %fiber.fp2, align 8
  ret i32 0

context_helper.prologue.overflow:                 ; preds = %context_helper.prologue
  %fiber.outcome = getelementptr inbounds nuw %fiber_control, ptr %fiber_control, i32 0, i32 0
  %6 = call i32 @bpf_capsule_set_outcome(i32 %fiber, i64 -30064771069), !dbg !45
  ret i32 0
}

; Function Attrs: noinline
define i32 @__bpf_capsule_trampoline_ctx_step(ptr "bpf.capsule.borrowed" %ctx, i32 %fiber, ptr "bpf.capsule.control" %fiber_control) #2 !dbg !46 {
entry:
  %0 = icmp ne ptr %fiber_control, null, !dbg !51
  br i1 %0, label %control.ready, label %control.missing, !dbg !51

iterate:                                          ; preds = %control.ready
  %fiber.pc = getelementptr inbounds nuw %fiber_control, ptr %fiber_control, i32 0, i32 5, !dbg !51
  %pc = load i32, ptr %fiber.pc, align 4, !dbg !51
  %1 = icmp eq i32 %pc, -1, !dbg !51
  %fiber.outcome = getelementptr inbounds nuw %fiber_control, ptr %fiber_control, i32 0, i32 0, !dbg !51
  %2 = load i64, ptr %fiber.outcome, align 8, !dbg !51
  %3 = icmp ne i64 %2, 0, !dbg !51
  %4 = icmp eq i32 %pc, 0, !dbg !51
  %5 = or i1 %1, %3, !dbg !51
  %6 = or i1 %4, %5, !dbg !51
  br i1 %6, label %terminal, label %route, !dbg !51

control.ready:                                    ; preds = %entry
  br label %iterate, !dbg !51

control.missing:                                  ; preds = %entry
  ret i32 1, !dbg !51

route:                                            ; preds = %iterate
  br label %route.lookup, !dbg !51

route.lookup:                                     ; preds = %route
  %7 = icmp ult i32 %pc, 5, !dbg !51
  br i1 %7, label %route.pc.ready, label %bad.id, !dbg !51

route.pc.ready:                                   ; preds = %route.lookup
  %8 = zext i32 %pc to i64, !dbg !51
  %9 = getelementptr inbounds [5 x i32], ptr @bpf_pc_unit, i64 0, i64 %8, !dbg !51
  %allocation.unit = load i32, ptr %9, align 4, !dbg !51
  br label %dispatch, !dbg !51

dispatch:                                         ; preds = %route.pc.ready
  switch i32 %allocation.unit, label %bad.id [
    i32 0, label %scalar.step
    i32 1, label %bpf.dispatch.output.ctx.0
  ], !dbg !51

bpf.dispatch.output.ctx.0:                        ; preds = %dispatch
  %10 = call i32 @bpf.dispatch.output.ctx.0(ptr %ctx, i32 %fiber, ptr %fiber_control, i32 %allocation.unit), !dbg !51
  ret i32 %10, !dbg !51

terminal:                                         ; preds = %iterate
  br i1 %1, label %completed, label %done, !dbg !51

completed:                                        ; preds = %terminal
  store i32 0, ptr %fiber.pc, align 4, !dbg !51
  br label %done, !dbg !51

scalar.step:                                      ; preds = %dispatch
  %11 = call i32 @__bpf_capsule_trampoline_step(i32 %fiber, ptr %fiber_control), !dbg !51
  ret i32 %11, !dbg !51

done:                                             ; preds = %completed, %terminal
  ret i32 1, !dbg !51

bad.id:                                           ; preds = %dispatch, %route.lookup
  %12 = call i32 @bpf_capsule_set_outcome(i32 %fiber, i64 -38654705661), !dbg !51
  ret i32 1, !dbg !51
}

; Function Attrs: noinline
define i32 @bpf.dispatch.output.ctx.0(ptr "bpf.capsule.borrowed" %ctx, i32 %fiber, ptr "bpf.capsule.control" %fiber_control, i32 %dispatch_key) #1 !dbg !52 !bpf.capsule.flatten.root !44 {
entry:
  %0 = icmp ne ptr %fiber_control, null, !dbg !60
  br i1 %0, label %dispatch, label %bad.id, !dbg !60

dispatch:                                         ; preds = %entry
  switch i32 %dispatch_key, label %bad.id [
    i32 1, label %bpf.unit.1
  ], !dbg !60

bad.id:                                           ; preds = %dispatch, %entry
  %1 = call i32 @bpf_capsule_set_outcome(i32 %fiber, i64 -38654705661), !dbg !60
  ret i32 1, !dbg !60

bpf.unit.1:                                       ; preds = %dispatch
  %2 = call i32 @bpf.unit.1(ptr %ctx, i32 %fiber, ptr %fiber_control), !dbg !60
  ret i32 %2, !dbg !60
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
!6 = distinct !DISubprogram(name: "start", scope: !2, file: !2, type: !7, spFlags: DISPFlagDefinition, unit: !1)
!7 = !DISubroutineType(types: !8)
!8 = !{!9, !10, !9}
!9 = !DIBasicType(name: "int", size: 32, encoding: DW_ATE_signed)
!10 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !11, size: 64)
!11 = distinct !DICompositeType(tag: DW_TAG_structure_type, name: "xdp_md", file: !2, size: 192)
!12 = !{}
!13 = !DILocation(line: 0, scope: !6)
!14 = distinct !DISubprogram(name: "bpf_capsule_set_outcome", linkageName: "bpf_capsule_set_outcome", scope: null, file: !2, type: !15, spFlags: DISPFlagDefinition, unit: !1, retainedNodes: !18)
!15 = !DISubroutineType(types: !16)
!16 = !{!9, !9, !17}
!17 = !DIBasicType(name: "long long", size: 64, encoding: DW_ATE_signed)
!18 = !{!19, !20}
!19 = !DILocalVariable(name: "a0", arg: 1, scope: !14, file: !2, type: !9)
!20 = !DILocalVariable(name: "a1", arg: 2, scope: !14, file: !2, type: !17)
!21 = !DILocation(line: 0, scope: !14)
!22 = distinct !DISubprogram(name: "__bpf_capsule_trampoline_step", linkageName: "__bpf_capsule_trampoline_step", scope: null, file: !2, type: !23, flags: DIFlagArtificial, spFlags: DISPFlagDefinition, unit: !1, retainedNodes: !31)
!23 = !DISubroutineType(types: !24)
!24 = !{!9, !25, !26}
!25 = !DIBasicType(name: "unsigned int", size: 32, encoding: DW_ATE_unsigned)
!26 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !27, size: 64)
!27 = !DICompositeType(tag: DW_TAG_array_type, baseType: !28, size: 320, align: 8, elements: !29)
!28 = !DIBasicType(name: "unsigned char", size: 8, encoding: DW_ATE_unsigned_char)
!29 = !{!30}
!30 = !DISubrange(count: 40, lowerBound: 0)
!31 = !{!32, !33}
!32 = !DILocalVariable(name: "fiber", arg: 1, scope: !22, file: !2, type: !25)
!33 = !DILocalVariable(name: "fiber_control", arg: 2, scope: !22, file: !2, type: !26)
!34 = !{i32 0}
!35 = !DILocation(line: 0, scope: !22)
!36 = distinct !DISubprogram(name: "bpf.unit.1", linkageName: "bpf.unit.1", scope: null, file: !2, type: !37, flags: DIFlagArtificial, spFlags: DISPFlagDefinition, unit: !1, retainedNodes: !39)
!37 = !DISubroutineType(types: !38)
!38 = !{!9, !10, !25, !26}
!39 = !{!40, !41, !42}
!40 = !DILocalVariable(name: "ctx", arg: 1, scope: !36, file: !2, type: !10)
!41 = !DILocalVariable(name: "fiber", arg: 2, scope: !36, file: !2, type: !25)
!42 = !DILocalVariable(name: "fiber_control", arg: 3, scope: !36, file: !2, type: !26)
!43 = !{i32 1}
!44 = !{i32 2}
!45 = !DILocation(line: 0, scope: !36)
!46 = distinct !DISubprogram(name: "__bpf_capsule_trampoline_ctx_step", linkageName: "__bpf_capsule_trampoline_ctx_step", scope: null, file: !2, type: !37, spFlags: DISPFlagDefinition, unit: !1, retainedNodes: !47)
!47 = !{!48, !49, !50}
!48 = !DILocalVariable(name: "ctx", arg: 1, scope: !46, file: !2, type: !10)
!49 = !DILocalVariable(name: "fiber", arg: 2, scope: !46, file: !2, type: !25)
!50 = !DILocalVariable(name: "fiber_control", arg: 3, scope: !46, file: !2, type: !26)
!51 = !DILocation(line: 0, scope: !46)
!52 = distinct !DISubprogram(name: "bpf.dispatch.output.ctx.0", linkageName: "bpf.dispatch.output.ctx.0", scope: null, file: !2, type: !53, spFlags: DISPFlagDefinition, unit: !1, retainedNodes: !55)
!53 = !DISubroutineType(types: !54)
!54 = !{!9, !10, !25, !26, !25}
!55 = !{!56, !57, !58, !59}
!56 = !DILocalVariable(name: "ctx", arg: 1, scope: !52, file: !2, type: !10)
!57 = !DILocalVariable(name: "fiber", arg: 2, scope: !52, file: !2, type: !25)
!58 = !DILocalVariable(name: "fiber_control", arg: 3, scope: !52, file: !2, type: !26)
!59 = !DILocalVariable(name: "dispatch_key", arg: 4, scope: !52, file: !2, type: !25)
!60 = !DILocation(line: 0, scope: !52)
