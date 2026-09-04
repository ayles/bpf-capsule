source_filename = "stackify-native-runtime-btf.c"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpfel"

%fiber_control = type { i32, i32, i64, i64, i64, i32, i32 }
%config = type { i32, i32, i32, i32, i32, i32, i32, i32, i32, i32, i32, i32, i64 }

@bpf_capsule_fibers = global [1 x %fiber_control] zeroinitializer, section ".bss.bpfctrl", align 8
@bpf_capsule_config = constant %config { i32 0, i32 4096, i32 0, i32 0, i32 1, i32 4096, i32 1, i32 0, i32 1, i32 0, i32 1112556353, i32 5, i64 0 }, section ".rodata.bpfconfig", align 4
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

define internal i64 @__bpf_runtime_glue(i32 %value) !dbg !20 {
entry:
  %wide = zext i32 %value to i64, !dbg !26
  ret i64 %wide, !dbg !26
}

define i32 @start(i32 %fiber) section "syscall" !bpf.native !27 {
entry:
  %native = call i64 @__bpf_runtime_glue(i32 7)
  %fiber.index = and i32 %fiber, 0
  %fiber.index1 = and i32 %fiber.index, 0
  %0 = zext i32 %fiber.index1 to i64
  %1 = mul i64 %0, 262144
  %stack.linear.offset = add i64 %1, 262112
  %fiber.stack = getelementptr i8, ptr @bpf_call_stack, i64 %stack.linear.offset
  %root.fp = ptrtoint ptr %fiber.stack to i64
  %fiber.index2 = and i32 %fiber.index, 0
  %fiber.control = getelementptr inbounds [1 x %fiber_control], ptr @bpf_capsule_fibers, i32 0, i32 %fiber.index2, !bpf.capsule.sectioned.bounded !27
  %fiber.outcome = getelementptr inbounds nuw %fiber_control, ptr %fiber.control, i32 0, i32 0
  store i64 0, ptr %fiber.outcome, align 8
  %root.saved.fp = getelementptr i8, ptr %fiber.stack, i64 0
  store i64 0, ptr %root.saved.fp, align 8
  %root.return.pc = getelementptr i8, ptr %fiber.stack, i64 8
  store i32 -1, ptr %root.return.pc, align 4
  %2 = getelementptr i8, ptr %fiber.stack, i64 24
  store i32 41, ptr %2, align 8
  %fiber.index3 = and i32 %fiber.index, 0
  %fiber.control4 = getelementptr inbounds [1 x %fiber_control], ptr @bpf_capsule_fibers, i32 0, i32 %fiber.index3, !bpf.capsule.sectioned.bounded !27
  %fiber.return.size = getelementptr inbounds nuw %fiber_control, ptr %fiber.control4, i32 0, i32 6
  store i32 4, ptr %fiber.return.size, align 4
  %fiber.index5 = and i32 %fiber.index, 0
  %fiber.control6 = getelementptr inbounds [1 x %fiber_control], ptr @bpf_capsule_fibers, i32 0, i32 %fiber.index5, !bpf.capsule.sectioned.bounded !27
  %fiber.pc = getelementptr inbounds nuw %fiber_control, ptr %fiber.control6, i32 0, i32 5
  store i32 1, ptr %fiber.pc, align 4
  %fiber.index7 = and i32 %fiber.index, 0
  %fiber.control8 = getelementptr inbounds [1 x %fiber_control], ptr @bpf_capsule_fibers, i32 0, i32 %fiber.index7, !bpf.capsule.sectioned.bounded !27
  %fiber.sp = getelementptr inbounds nuw %fiber_control, ptr %fiber.control8, i32 0, i32 3
  store i64 %root.fp, ptr %fiber.sp, align 8
  %fiber.index9 = and i32 %fiber.index, 0
  %fiber.control10 = getelementptr inbounds [1 x %fiber_control], ptr @bpf_capsule_fibers, i32 0, i32 %fiber.index9, !bpf.capsule.sectioned.bounded !27
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
define i32 @bpf_capsule_set_outcome(i32 %fiber, i64 %outcome) #1 !dbg !28 !bpf.native.scalar !27 {
entry:
  %fiber.index = and i32 %fiber, 0, !dbg !34
  %fiber.control = getelementptr inbounds [1 x %fiber_control], ptr @bpf_capsule_fibers, i32 0, i32 %fiber.index, !dbg !34, !bpf.capsule.sectioned.bounded !27
  %fiber.outcome = getelementptr inbounds nuw %fiber_control, ptr %fiber.control, i32 0, i32 0, !dbg !34
  store volatile i64 %outcome, ptr %fiber.outcome, align 8, !dbg !34
  ret i32 0, !dbg !34
}

; Function Attrs: noinline
define i32 @__bpf_capsule_trampoline_step(i32 %fiber, ptr "bpf.capsule.control" %fiber_control) #2 !dbg !35 !bpf.capsule !27 !bpf.capsule.allocation.unit !39 !bpf.capsule.stack.size !0 {
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
  %fiber.fp = getelementptr inbounds nuw %fiber_control, ptr %fiber_control, i32 0, i32 4, !dbg !40
  %frame.fp = load i64, ptr %fiber.fp, align 8, !dbg !40
  %frame.addr = inttoptr i64 %frame.fp to ptr, !dbg !40
  %fiber.index = and i32 %fiber, 0, !dbg !40
  %7 = zext i32 %fiber.index to i64, !dbg !40
  %8 = mul i64 %7, 262144, !dbg !40
  %stack.linear.offset = add i64 %8, 0, !dbg !40
  %fiber.stack = getelementptr i8, ptr @bpf_call_stack, i64 %stack.linear.offset, !dbg !40
  call void asm sideeffect "# bpf_capsule_stack_anchor", "r"(ptr %fiber.stack), !dbg !40
  %fiber.pc4 = getelementptr inbounds nuw %fiber_control, ptr %fiber_control, i32 0, i32 5, !dbg !40
  %pc5 = load i32, ptr %fiber.pc4, align 4, !dbg !40
  %9 = icmp ult i32 %pc5, 2, !dbg !40
  br i1 %9, label %unit.test.left, label %unit.test.right, !dbg !40

unit.control.missing:                             ; preds = %unit.entry
  ret i32 1

root.prologue:                                    ; preds = %unit.test.left
  %frame.sp = sub i64 %frame.fp, 0
  %slice.offset = and i64 %frame.fp, 262143
  %10 = icmp ult i64 %slice.offset, 131072
  br i1 %10, label %root.prologue.overflow, label %entry

entry:                                            ; preds = %root.prologue
  %fiber.sp = getelementptr inbounds nuw %fiber_control, ptr %fiber_control, i32 0, i32 3
  store i64 %frame.sp, ptr %fiber.sp, align 8
  %fiber.pc3 = getelementptr inbounds nuw %fiber_control, ptr %fiber_control, i32 0, i32 5
  store i32 2, ptr %fiber.pc3, align 4
  %fiber.outcome4 = getelementptr inbounds nuw %fiber_control, ptr %fiber_control, i32 0, i32 0
  store i64 2, ptr %fiber.outcome4, align 8
  ret i32 1

root.prologue.overflow:                           ; preds = %root.prologue
  %fiber.outcome = getelementptr inbounds nuw %fiber_control, ptr %fiber_control, i32 0, i32 0
  %11 = call i32 @bpf_capsule_set_outcome(i32 %fiber, i64 -30064771069), !dbg !40
  ret i32 0

entry.yield.resume:                               ; preds = %unit.test.right
  %12 = getelementptr i8, ptr %frame.addr, i64 24
  %value = load i32, ptr %12, align 4
  %result = add i32 %value, 1
  %result.slot = getelementptr i8, ptr %frame.addr, i64 16
  store i32 %result, ptr %result.slot, align 8
  %13 = getelementptr i8, ptr %frame.addr, i64 8
  %return.pc = load i32, ptr %13, align 4
  %14 = getelementptr i8, ptr %frame.addr, i64 0
  %saved.fp = load i64, ptr %14, align 8
  %fiber.pc = getelementptr inbounds nuw %fiber_control, ptr %fiber_control, i32 0, i32 5
  store i32 %return.pc, ptr %fiber.pc, align 4
  %return.sp = add i64 %frame.fp, 16
  %fiber.sp1 = getelementptr inbounds nuw %fiber_control, ptr %fiber_control, i32 0, i32 3
  store i64 %return.sp, ptr %fiber.sp1, align 8
  %fiber.fp2 = getelementptr inbounds nuw %fiber_control, ptr %fiber_control, i32 0, i32 4
  store i64 %saved.fp, ptr %fiber.fp2, align 8
  ret i32 0

unit.test.left:                                   ; preds = %unit.control.ready
  %15 = icmp eq i32 %pc5, 1
  br i1 %15, label %root.prologue, label %unit.unknown

unit.test.right:                                  ; preds = %unit.control.ready
  %16 = icmp eq i32 %pc5, 2
  br i1 %16, label %entry.yield.resume, label %unit.unknown

unit.unknown:                                     ; preds = %unit.test.right, %unit.test.left
  %17 = call i32 @bpf_capsule_set_outcome(i32 %fiber, i64 -38654705661), !dbg !40
  ret i32 0, !dbg !40
}

attributes #0 = { "capsule.trampoline" }
attributes #1 = { noinline }
attributes #2 = { noinline "capsule.trampoline" }

!llvm.dbg.cu = !{!1}
!llvm.module.flags = !{!3, !4, !5}

!0 = !{i64 262144}
!1 = distinct !DICompileUnit(language: DW_LANG_C11, file: !2, producer: "pass contract", isOptimized: true, runtimeVersion: 0, emissionKind: FullDebug, splitDebugInlining: false, nameTableKind: None)
!2 = !DIFile(filename: "stackify-native-runtime-btf.c", directory: "/")
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
!20 = distinct !DISubprogram(name: "__bpf_runtime_glue", linkageName: "__bpf_runtime_glue", scope: null, file: !2, type: !21, spFlags: DISPFlagLocalToUnit | DISPFlagDefinition, unit: !1, retainedNodes: !24)
!21 = !DISubroutineType(types: !22)
!22 = !{!23, !9}
!23 = !DIBasicType(name: "long long", size: 64, encoding: DW_ATE_signed)
!24 = !{!25}
!25 = !DILocalVariable(name: "a0", arg: 1, scope: !20, file: !2, type: !9)
!26 = !DILocation(line: 0, scope: !20)
!27 = !{}
!28 = distinct !DISubprogram(name: "bpf_capsule_set_outcome", linkageName: "bpf_capsule_set_outcome", scope: null, file: !2, type: !29, spFlags: DISPFlagDefinition, unit: !1, retainedNodes: !31)
!29 = !DISubroutineType(types: !30)
!30 = !{!9, !9, !23}
!31 = !{!32, !33}
!32 = !DILocalVariable(name: "a0", arg: 1, scope: !28, file: !2, type: !9)
!33 = !DILocalVariable(name: "a1", arg: 2, scope: !28, file: !2, type: !23)
!34 = !DILocation(line: 0, scope: !28)
!35 = distinct !DISubprogram(name: "__bpf_capsule_trampoline_step", linkageName: "__bpf_capsule_trampoline_step", scope: null, file: !2, type: !7, flags: DIFlagArtificial, spFlags: DISPFlagDefinition, unit: !1, retainedNodes: !36)
!36 = !{!37, !38}
!37 = !DILocalVariable(name: "fiber", arg: 1, scope: !35, file: !2, type: !10)
!38 = !DILocalVariable(name: "fiber_control", arg: 2, scope: !35, file: !2, type: !11)
!39 = !{i32 0}
!40 = !DILocation(line: 0, scope: !35)
