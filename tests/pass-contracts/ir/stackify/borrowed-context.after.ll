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

define i32 @start(ptr %context, i32 %fiber) section "xdp" !bpf.native !6 {
entry:
  %fiber.index = and i32 %fiber, 0
  %fiber.index1 = and i32 %fiber.index, 0
  %0 = zext i32 %fiber.index1 to i64
  %1 = mul i64 %0, 262144
  %stack.linear.offset = add i64 %1, 262128
  %fiber.stack = getelementptr i8, ptr @bpf_call_stack, i64 %stack.linear.offset
  %root.fp = ptrtoint ptr %fiber.stack to i64
  %fiber.index2 = and i32 %fiber.index, 0
  %fiber.control = getelementptr inbounds [1 x %fiber_control], ptr @bpf_capsule_fibers, i32 0, i32 %fiber.index2, !bpf.capsule.sectioned.bounded !6
  %fiber.outcome = getelementptr inbounds nuw %fiber_control, ptr %fiber.control, i32 0, i32 0
  store i64 0, ptr %fiber.outcome, align 8
  %root.return.pc = getelementptr i8, ptr %fiber.stack, i64 -8
  store i32 -1, ptr %root.return.pc, align 4
  %root.saved.fp = getelementptr i8, ptr %fiber.stack, i64 -16
  store i64 0, ptr %root.saved.fp, align 8
  %fiber.index3 = and i32 %fiber.index, 0
  %fiber.control4 = getelementptr inbounds [1 x %fiber_control], ptr @bpf_capsule_fibers, i32 0, i32 %fiber.index3, !bpf.capsule.sectioned.bounded !6
  %fiber.return.size = getelementptr inbounds nuw %fiber_control, ptr %fiber.control4, i32 0, i32 6
  store i32 4, ptr %fiber.return.size, align 4
  %fiber.index5 = and i32 %fiber.index, 0
  %fiber.control6 = getelementptr inbounds [1 x %fiber_control], ptr @bpf_capsule_fibers, i32 0, i32 %fiber.index5, !bpf.capsule.sectioned.bounded !6
  %fiber.pc = getelementptr inbounds nuw %fiber_control, ptr %fiber.control6, i32 0, i32 5
  store i32 1, ptr %fiber.pc, align 4
  %fiber.index7 = and i32 %fiber.index, 0
  %fiber.control8 = getelementptr inbounds [1 x %fiber_control], ptr @bpf_capsule_fibers, i32 0, i32 %fiber.index7, !bpf.capsule.sectioned.bounded !6
  %fiber.sp = getelementptr inbounds nuw %fiber_control, ptr %fiber.control8, i32 0, i32 3
  store i64 %root.fp, ptr %fiber.sp, align 8
  %fiber.index9 = and i32 %fiber.index, 0
  %fiber.control10 = getelementptr inbounds [1 x %fiber_control], ptr @bpf_capsule_fibers, i32 0, i32 %fiber.index9, !bpf.capsule.sectioned.bounded !6
  %fiber.fp = getelementptr inbounds nuw %fiber_control, ptr %fiber.control10, i32 0, i32 4
  store i64 %root.fp, ptr %fiber.fp, align 8
  %control.i = getelementptr [1 x %fiber_control], ptr @bpf_capsule_fibers, i32 0, i32 %fiber.index
  %status.i = call i32 @__bpf_capsule_trampoline_ctx_l1(ptr %context, i32 %fiber.index, ptr %control.i)
  %fiber.index11 = and i32 %fiber.index, 0
  %2 = zext i32 %fiber.index11 to i64
  %3 = mul i64 %2, 262144
  %stack.linear.offset12 = add i64 %3, 262128
  %fiber.stack13 = getelementptr i8, ptr @bpf_call_stack, i64 %stack.linear.offset12
  %root.result = load i32, ptr %fiber.stack13, align 4
  ret i32 %root.result
}

; Function Attrs: noinline
define i32 @bpf_capsule_set_outcome(i32 %fiber, i64 %outcome) #1 !dbg !7 !bpf.native.scalar !6 {
entry:
  %fiber.index = and i32 %fiber, 0, !dbg !15
  %fiber.control = getelementptr inbounds [1 x %fiber_control], ptr @bpf_capsule_fibers, i32 0, i32 %fiber.index, !dbg !15, !bpf.capsule.sectioned.bounded !6
  %fiber.outcome = getelementptr inbounds nuw %fiber_control, ptr %fiber.control, i32 0, i32 0, !dbg !15
  store volatile i64 %outcome, ptr %fiber.outcome, align 8, !dbg !15
  ret i32 0, !dbg !15
}

; Function Attrs: noinline
define i32 @bpf.unit.0(ptr "bpf.capsule.borrowed" %ctx, i32 %fiber, ptr "bpf.capsule.control" %fiber_control) #1 !dbg !16 !bpf.capsule !6 !bpf.capsule.allocation.unit !31 !bpf.capsule.stack.size !0 !bpf.capsule.flatten.unit !32 {
unit.entry:
  %fiber.fp = getelementptr inbounds nuw %fiber_control, ptr %fiber_control, i32 0, i32 4, !dbg !33
  %frame.fp = load i64, ptr %fiber.fp, align 8, !dbg !33
  %frame.addr = inttoptr i64 %frame.fp to ptr, !dbg !33
  %fiber.index = and i32 %fiber, 0, !dbg !33
  %0 = zext i32 %fiber.index to i64, !dbg !33
  %1 = mul i64 %0, 262144, !dbg !33
  %stack.linear.offset = add i64 %1, 0, !dbg !33
  %fiber.stack = getelementptr i8, ptr @bpf_call_stack, i64 %stack.linear.offset, !dbg !33
  call void asm sideeffect "# bpf_capsule_stack_anchor", "r"(ptr %fiber.stack), !dbg !33
  %fiber.pc1 = getelementptr inbounds nuw %fiber_control, ptr %fiber_control, i32 0, i32 5, !dbg !33
  %pc = load i32, ptr %fiber.pc1, align 4, !dbg !33
  %2 = icmp ult i32 %pc, 3, !dbg !33
  br i1 %2, label %unit.test.left, label %unit.test.right, !dbg !33

borrowed_root.prologue:                           ; preds = %unit.test.left
  %frame.sp = sub i64 %frame.fp, 48
  %slice.offset = and i64 %frame.fp, 262143
  %3 = icmp ult i64 %slice.offset, 131152
  br i1 %3, label %borrowed_root.prologue.overflow, label %entry, !dbg !33

entry:                                            ; preds = %borrowed_root.prologue
  %fiber.sp = getelementptr inbounds nuw %fiber_control, ptr %fiber_control, i32 0, i32 3, !dbg !33
  store i64 %frame.sp, ptr %fiber.sp, align 8, !dbg !33
  %callee.fp = sub i64 %frame.fp, 48, !dbg !33
  %return.pc.slot = getelementptr i8, ptr %frame.addr, i64 -56, !dbg !33
  store i32 3, ptr %return.pc.slot, align 4, !dbg !33
  %saved.fp.slot = getelementptr i8, ptr %frame.addr, i64 -64, !dbg !33
  store i64 %frame.fp, ptr %saved.fp.slot, align 8, !dbg !33
  %4 = getelementptr i8, ptr %frame.addr, i64 -80, !dbg !33
  store i32 5, ptr %4, align 4, !dbg !33
  %fiber.pc4 = getelementptr inbounds nuw %fiber_control, ptr %fiber_control, i32 0, i32 5, !dbg !33
  store i32 2, ptr %fiber.pc4, align 4, !dbg !33
  %fiber.fp5 = getelementptr inbounds nuw %fiber_control, ptr %fiber_control, i32 0, i32 4, !dbg !33
  store i64 %callee.fp, ptr %fiber.fp5, align 8, !dbg !33
  ret i32 0, !dbg !33

borrowed_root.prologue.overflow:                  ; preds = %borrowed_root.prologue
  %fiber.outcome = getelementptr inbounds nuw %fiber_control, ptr %fiber_control, i32 0, i32 0
  %5 = call i32 @bpf_capsule_set_outcome(i32 %fiber, i64 -30064771069), !dbg !33
  ret i32 0, !dbg !33

entry.resume:                                     ; preds = %unit.test.left2
  %result.zone = getelementptr i8, ptr %frame.addr, i64 -48, !dbg !33
  %callret = load i32, ptr %result.zone, align 4, !dbg !33
  %callee.fp6 = sub i64 %frame.fp, 48, !dbg !33
  %return.pc.slot7 = getelementptr i8, ptr %frame.addr, i64 -56, !dbg !33
  store i32 4, ptr %return.pc.slot7, align 4, !dbg !33
  %saved.fp.slot8 = getelementptr i8, ptr %frame.addr, i64 -64, !dbg !33
  store i64 %frame.fp, ptr %saved.fp.slot8, align 8, !dbg !33
  %6 = getelementptr i8, ptr %frame.addr, i64 -80, !dbg !33
  store i32 %callret, ptr %6, align 4, !dbg !33
  %fiber.pc9 = getelementptr inbounds nuw %fiber_control, ptr %fiber_control, i32 0, i32 5, !dbg !33
  store i32 2, ptr %fiber.pc9, align 4, !dbg !33
  %fiber.fp10 = getelementptr inbounds nuw %fiber_control, ptr %fiber_control, i32 0, i32 4, !dbg !33
  store i64 %callee.fp6, ptr %fiber.fp10, align 8, !dbg !33
  ret i32 0, !dbg !33

entry.resume.resume:                              ; preds = %unit.test.right3
  %result.zone11 = getelementptr i8, ptr %frame.addr, i64 -48
  %callret12 = load i32, ptr %result.zone11, align 4
  store i32 %callret12, ptr %frame.addr, align 4
  %7 = getelementptr i8, ptr %frame.addr, i64 -8
  %return.pc = load i32, ptr %7, align 4
  %8 = getelementptr i8, ptr %frame.addr, i64 -16
  %saved.fp = load i64, ptr %8, align 8
  %fiber.pc = getelementptr inbounds nuw %fiber_control, ptr %fiber_control, i32 0, i32 5
  store i32 %return.pc, ptr %fiber.pc, align 4
  %fiber.sp2 = getelementptr inbounds nuw %fiber_control, ptr %fiber_control, i32 0, i32 3
  store i64 %frame.fp, ptr %fiber.sp2, align 8
  %fiber.fp3 = getelementptr inbounds nuw %fiber_control, ptr %fiber_control, i32 0, i32 4
  store i64 %saved.fp, ptr %fiber.fp3, align 8
  ret i32 0, !dbg !33

unit.test.left:                                   ; preds = %unit.entry
  br label %borrowed_root.prologue

unit.test.right:                                  ; preds = %unit.entry
  %9 = icmp ult i32 %pc, 4
  br i1 %9, label %unit.test.left2, label %unit.test.right3

unit.test.left2:                                  ; preds = %unit.test.right
  br label %entry.resume

unit.test.right3:                                 ; preds = %unit.test.right
  br label %entry.resume.resume
}

; Function Attrs: noinline
define i32 @bpf.unit.1(ptr "bpf.capsule.borrowed" %ctx, i32 %fiber, ptr "bpf.capsule.control" %fiber_control) #1 !dbg !34 !bpf.capsule !6 !bpf.capsule.allocation.unit !31 !bpf.capsule.stack.size !0 !bpf.capsule.flatten.unit !32 {
unit.entry:
  %fiber.fp = getelementptr inbounds nuw %fiber_control, ptr %fiber_control, i32 0, i32 4, !dbg !39
  %frame.fp = load i64, ptr %fiber.fp, align 8, !dbg !39
  %frame.addr = inttoptr i64 %frame.fp to ptr, !dbg !39
  %fiber.index = and i32 %fiber, 0, !dbg !39
  %0 = zext i32 %fiber.index to i64, !dbg !39
  %1 = mul i64 %0, 262144, !dbg !39
  %stack.linear.offset = add i64 %1, 0, !dbg !39
  %fiber.stack = getelementptr i8, ptr @bpf_call_stack, i64 %stack.linear.offset, !dbg !39
  call void asm sideeffect "# bpf_capsule_stack_anchor", "r"(ptr %fiber.stack), !dbg !39
  %fiber.pc1 = getelementptr inbounds nuw %fiber_control, ptr %fiber_control, i32 0, i32 5, !dbg !39
  %pc = load i32, ptr %fiber.pc1, align 4, !dbg !39
  br label %context_helper.prologue, !dbg !39

context_helper.prologue:                          ; preds = %unit.entry
  %frame.sp = sub i64 %frame.fp, 32
  %slice.offset = and i64 %frame.fp, 262143
  %2 = icmp ult i64 %slice.offset, 131136
  br i1 %2, label %context_helper.prologue.overflow, label %entry

entry:                                            ; preds = %context_helper.prologue
  %fiber.sp = getelementptr inbounds nuw %fiber_control, ptr %fiber_control, i32 0, i32 3
  store i64 %frame.sp, ptr %fiber.sp, align 8
  call void asm sideeffect "", "r"(ptr %ctx), !dbg !39
  %3 = getelementptr i8, ptr %frame.addr, i64 -32
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
  %6 = call i32 @bpf_capsule_set_outcome(i32 %fiber, i64 -30064771069), !dbg !39
  ret i32 0
}

; Function Attrs: noinline
define i32 @__bpf_capsule_trampoline_ctx_step(ptr "bpf.capsule.borrowed" %ctx, i32 %fiber, ptr "bpf.capsule.control" %fiber_control) #2 !dbg !40 {
entry:
  %0 = icmp ne ptr %fiber_control, null, !dbg !45
  br i1 %0, label %control.ready, label %control.missing, !dbg !45

iterate:                                          ; preds = %control.ready
  %fiber.pc = getelementptr inbounds nuw %fiber_control, ptr %fiber_control, i32 0, i32 5, !dbg !45
  %pc = load i32, ptr %fiber.pc, align 4, !dbg !45
  %1 = icmp eq i32 %pc, -1, !dbg !45
  %fiber.outcome = getelementptr inbounds nuw %fiber_control, ptr %fiber_control, i32 0, i32 0, !dbg !45
  %2 = load i64, ptr %fiber.outcome, align 8, !dbg !45
  %3 = icmp ne i64 %2, 0, !dbg !45
  %4 = icmp eq i32 %pc, 0, !dbg !45
  %5 = or i1 %1, %3, !dbg !45
  %6 = or i1 %4, %5, !dbg !45
  br i1 %6, label %terminal, label %route, !dbg !45

control.ready:                                    ; preds = %entry
  br label %iterate, !dbg !45

control.missing:                                  ; preds = %entry
  ret i32 1, !dbg !45

route:                                            ; preds = %iterate
  br label %route.lookup, !dbg !45

route.lookup:                                     ; preds = %route
  %7 = icmp ult i32 %pc, 5, !dbg !45
  br i1 %7, label %route.pc.ready, label %bad.id, !dbg !45

route.pc.ready:                                   ; preds = %route.lookup
  %8 = zext i32 %pc to i64, !dbg !45
  %9 = getelementptr inbounds [5 x i32], ptr @bpf_pc_unit, i64 0, i64 %8, !dbg !45
  %allocation.unit = load i32, ptr %9, align 4, !dbg !45
  br label %dispatch, !dbg !45

dispatch:                                         ; preds = %route.pc.ready
  switch i32 %allocation.unit, label %bad.id [
    i32 0, label %bpf.dispatch.output.ctx.0
    i32 1, label %bpf.dispatch.output.ctx.0
  ], !dbg !45

bpf.dispatch.output.ctx.0:                        ; preds = %dispatch, %dispatch
  %10 = call i32 @bpf.dispatch.output.ctx.0(ptr %ctx, i32 %fiber, ptr %fiber_control, i32 %allocation.unit), !dbg !45
  ret i32 %10, !dbg !45

terminal:                                         ; preds = %iterate
  br i1 %1, label %completed, label %done, !dbg !45

completed:                                        ; preds = %terminal
  store i32 0, ptr %fiber.pc, align 4, !dbg !45
  br label %done, !dbg !45

done:                                             ; preds = %completed, %terminal
  ret i32 1, !dbg !45

bad.id:                                           ; preds = %dispatch, %route.lookup
  %11 = call i32 @bpf_capsule_set_outcome(i32 %fiber, i64 -38654705661), !dbg !45
  ret i32 1, !dbg !45
}

; Function Attrs: noinline
define i32 @bpf.dispatch.output.ctx.0(ptr "bpf.capsule.borrowed" %ctx, i32 %fiber, ptr "bpf.capsule.control" %fiber_control, i32 %dispatch_key) #1 !dbg !46 !bpf.capsule.flatten.root !32 {
entry:
  %0 = icmp ne ptr %fiber_control, null, !dbg !54
  br i1 %0, label %dispatch, label %bad.id, !dbg !54

dispatch:                                         ; preds = %entry
  switch i32 %dispatch_key, label %bad.id [
    i32 0, label %bpf.unit.0
    i32 1, label %bpf.unit.1
  ], !dbg !54

bad.id:                                           ; preds = %dispatch, %entry
  %1 = call i32 @bpf_capsule_set_outcome(i32 %fiber, i64 -38654705661), !dbg !54
  ret i32 1, !dbg !54

bpf.unit.0:                                       ; preds = %dispatch
  %2 = call i32 @bpf.unit.0(ptr %ctx, i32 %fiber, ptr %fiber_control), !dbg !54
  ret i32 %2, !dbg !54

bpf.unit.1:                                       ; preds = %dispatch
  %3 = call i32 @bpf.unit.1(ptr %ctx, i32 %fiber, ptr %fiber_control), !dbg !54
  ret i32 %3, !dbg !54
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
!6 = !{}
!7 = distinct !DISubprogram(name: "bpf_capsule_set_outcome", linkageName: "bpf_capsule_set_outcome", scope: null, file: !2, type: !8, spFlags: DISPFlagDefinition, unit: !1, retainedNodes: !12)
!8 = !DISubroutineType(types: !9)
!9 = !{!10, !10, !11}
!10 = !DIBasicType(name: "int", size: 32, encoding: DW_ATE_signed)
!11 = !DIBasicType(name: "long long", size: 64, encoding: DW_ATE_signed)
!12 = !{!13, !14}
!13 = !DILocalVariable(name: "a0", arg: 1, scope: !7, file: !2, type: !10)
!14 = !DILocalVariable(name: "a1", arg: 2, scope: !7, file: !2, type: !11)
!15 = !DILocation(line: 0, scope: !7)
!16 = distinct !DISubprogram(name: "bpf.unit.0", linkageName: "bpf.unit.0", scope: null, file: !2, type: !17, flags: DIFlagArtificial, spFlags: DISPFlagDefinition, unit: !1, retainedNodes: !27)
!17 = !DISubroutineType(types: !18)
!18 = !{!10, !19, !21, !22}
!19 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !20, size: 64)
!20 = distinct !DICompositeType(tag: DW_TAG_structure_type, name: "xdp_md", file: !2, size: 192)
!21 = !DIBasicType(name: "unsigned int", size: 32, encoding: DW_ATE_unsigned)
!22 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !23, size: 64)
!23 = !DICompositeType(tag: DW_TAG_array_type, baseType: !24, size: 320, align: 8, elements: !25)
!24 = !DIBasicType(name: "unsigned char", size: 8, encoding: DW_ATE_unsigned_char)
!25 = !{!26}
!26 = !DISubrange(count: 40, lowerBound: 0)
!27 = !{!28, !29, !30}
!28 = !DILocalVariable(name: "ctx", arg: 1, scope: !16, file: !2, type: !19)
!29 = !DILocalVariable(name: "fiber", arg: 2, scope: !16, file: !2, type: !21)
!30 = !DILocalVariable(name: "fiber_control", arg: 3, scope: !16, file: !2, type: !22)
!31 = !{i32 1}
!32 = !{i32 2}
!33 = !DILocation(line: 0, scope: !16)
!34 = distinct !DISubprogram(name: "bpf.unit.1", linkageName: "bpf.unit.1", scope: null, file: !2, type: !17, flags: DIFlagArtificial, spFlags: DISPFlagDefinition, unit: !1, retainedNodes: !35)
!35 = !{!36, !37, !38}
!36 = !DILocalVariable(name: "ctx", arg: 1, scope: !34, file: !2, type: !19)
!37 = !DILocalVariable(name: "fiber", arg: 2, scope: !34, file: !2, type: !21)
!38 = !DILocalVariable(name: "fiber_control", arg: 3, scope: !34, file: !2, type: !22)
!39 = !DILocation(line: 0, scope: !34)
!40 = distinct !DISubprogram(name: "__bpf_capsule_trampoline_ctx_step", linkageName: "__bpf_capsule_trampoline_ctx_step", scope: null, file: !2, type: !17, spFlags: DISPFlagDefinition, unit: !1, retainedNodes: !41)
!41 = !{!42, !43, !44}
!42 = !DILocalVariable(name: "ctx", arg: 1, scope: !40, file: !2, type: !19)
!43 = !DILocalVariable(name: "fiber", arg: 2, scope: !40, file: !2, type: !21)
!44 = !DILocalVariable(name: "fiber_control", arg: 3, scope: !40, file: !2, type: !22)
!45 = !DILocation(line: 0, scope: !40)
!46 = distinct !DISubprogram(name: "bpf.dispatch.output.ctx.0", linkageName: "bpf.dispatch.output.ctx.0", scope: null, file: !2, type: !47, spFlags: DISPFlagDefinition, unit: !1, retainedNodes: !49)
!47 = !DISubroutineType(types: !48)
!48 = !{!10, !19, !21, !22, !21}
!49 = !{!50, !51, !52, !53}
!50 = !DILocalVariable(name: "ctx", arg: 1, scope: !46, file: !2, type: !19)
!51 = !DILocalVariable(name: "fiber", arg: 2, scope: !46, file: !2, type: !21)
!52 = !DILocalVariable(name: "fiber_control", arg: 3, scope: !46, file: !2, type: !22)
!53 = !DILocalVariable(name: "dispatch_key", arg: 4, scope: !46, file: !2, type: !21)
!54 = !DILocation(line: 0, scope: !46)
