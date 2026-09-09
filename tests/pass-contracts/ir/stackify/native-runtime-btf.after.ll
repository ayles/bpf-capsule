source_filename = "stackify-native-runtime-btf.c"
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

define internal i64 @__bpf_runtime_glue(i32 %value) !dbg !22 {
entry:
  %wide = zext i32 %value to i64, !dbg !28
  ret i64 %wide, !dbg !28
}

define i32 @start(i32 %fiber) section "syscall" !bpf.native !29 {
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
  %fiber.control = getelementptr inbounds [1 x %fiber_control], ptr @bpf_capsule_fibers, i32 0, i32 %fiber.index2, !bpf.capsule.sectioned.bounded !29
  %fiber.outcome = getelementptr inbounds nuw %fiber_control, ptr %fiber.control, i32 0, i32 0
  store i64 0, ptr %fiber.outcome, align 8
  %root.saved.fp = getelementptr i8, ptr %fiber.stack, i64 0
  store i64 0, ptr %root.saved.fp, align 8
  %root.return.region.id = getelementptr i8, ptr %fiber.stack, i64 8
  store i32 -1, ptr %root.return.region.id, align 4
  %2 = getelementptr i8, ptr %fiber.stack, i64 24
  store i32 41, ptr %2, align 8
  %fiber.index3 = and i32 %fiber.index, 0
  %fiber.control4 = getelementptr inbounds [1 x %fiber_control], ptr @bpf_capsule_fibers, i32 0, i32 %fiber.index3, !bpf.capsule.sectioned.bounded !29
  %fiber.return.size = getelementptr inbounds nuw %fiber_control, ptr %fiber.control4, i32 0, i32 6
  store i32 4, ptr %fiber.return.size, align 4
  %fiber.index5 = and i32 %fiber.index, 0
  %fiber.control6 = getelementptr inbounds [1 x %fiber_control], ptr @bpf_capsule_fibers, i32 0, i32 %fiber.index5, !bpf.capsule.sectioned.bounded !29
  %fiber.resume.region.id = getelementptr inbounds nuw %fiber_control, ptr %fiber.control6, i32 0, i32 5
  store i32 256, ptr %fiber.resume.region.id, align 4
  %fiber.index7 = and i32 %fiber.index, 0
  %fiber.control8 = getelementptr inbounds [1 x %fiber_control], ptr @bpf_capsule_fibers, i32 0, i32 %fiber.index7, !bpf.capsule.sectioned.bounded !29
  %fiber.sp = getelementptr inbounds nuw %fiber_control, ptr %fiber.control8, i32 0, i32 3
  store i64 %root.fp, ptr %fiber.sp, align 8
  %fiber.index9 = and i32 %fiber.index, 0
  %fiber.control10 = getelementptr inbounds [1 x %fiber_control], ptr @bpf_capsule_fibers, i32 0, i32 %fiber.index9, !bpf.capsule.sectioned.bounded !29
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
define i32 @bpf_capsule_set_outcome(i32 %fiber, i64 %outcome) #1 !dbg !30 !bpf.native.scalar !29 {
entry:
  %fiber.index = and i32 %fiber, 0, !dbg !36
  %fiber.control = getelementptr inbounds [1 x %fiber_control], ptr @bpf_capsule_fibers, i32 0, i32 %fiber.index, !dbg !36, !bpf.capsule.sectioned.bounded !29
  %fiber.outcome = getelementptr inbounds nuw %fiber_control, ptr %fiber.control, i32 0, i32 0, !dbg !36
  store volatile i64 %outcome, ptr %fiber.outcome, align 8, !dbg !36
  ret i32 0, !dbg !36
}

; Function Attrs: noinline
define i32 @bpf.unit.0(i32 %fiber, ptr "bpf.capsule.control" %fiber_control, i32 %region) #1 !dbg !37 !bpf.capsule !29 !bpf.capsule.allocation.unit !44 !bpf.capsule.stack.size !0 !bpf.capsule.flatten.unit !45 {
unit.entry:
  %fiber.fp = getelementptr inbounds nuw %fiber_control, ptr %fiber_control, i32 0, i32 4
  %frame.fp = load i64, ptr %fiber.fp, align 8
  %frame.addr = inttoptr i64 %frame.fp to ptr
  call void asm sideeffect "# bpf_capsule_stack_anchor", "r"(ptr %fiber_control), !dbg !46
  br label %unit.dispatch

unit.dispatch:                                    ; preds = %unit.entry
  br label %unit.dispatch1

root.prologue:                                    ; preds = %unit.test.left
  %frame.sp = sub i64 %frame.fp, 0
  %slice.offset = and i64 %frame.fp, 262143
  %0 = icmp ult i64 %slice.offset, 131072
  br i1 %0, label %root.prologue.overflow, label %entry

entry:                                            ; preds = %root.prologue
  %fiber.sp = getelementptr inbounds nuw %fiber_control, ptr %fiber_control, i32 0, i32 3
  store i64 %frame.sp, ptr %fiber.sp, align 8
  %fiber.resume.region.id3 = getelementptr inbounds nuw %fiber_control, ptr %fiber_control, i32 0, i32 5
  store i32 512, ptr %fiber.resume.region.id3, align 4
  %fiber.outcome4 = getelementptr inbounds nuw %fiber_control, ptr %fiber_control, i32 0, i32 0
  store i64 2, ptr %fiber.outcome4, align 8
  ret i32 1

root.prologue.overflow:                           ; preds = %root.prologue
  %fiber.outcome = getelementptr inbounds nuw %fiber_control, ptr %fiber_control, i32 0, i32 0
  %1 = call i32 @bpf_capsule_set_outcome(i32 %fiber, i64 -30064771069), !dbg !46
  ret i32 1

entry.yield.resume:                               ; preds = %unit.test.right
  %2 = getelementptr i8, ptr %frame.addr, i64 24
  %value = load i32, ptr %2, align 4
  %result = add i32 %value, 1
  %result.slot = getelementptr i8, ptr %frame.addr, i64 16
  store i32 %result, ptr %result.slot, align 8
  %3 = getelementptr i8, ptr %frame.addr, i64 8
  %return.region.id = load i32, ptr %3, align 4
  %4 = getelementptr i8, ptr %frame.addr, i64 0
  %saved.fp = load i64, ptr %4, align 8
  %fiber.resume.region.id = getelementptr inbounds nuw %fiber_control, ptr %fiber_control, i32 0, i32 5
  store i32 %return.region.id, ptr %fiber.resume.region.id, align 4
  %return.sp = add i64 %frame.fp, 16
  %fiber.sp1 = getelementptr inbounds nuw %fiber_control, ptr %fiber_control, i32 0, i32 3
  store i64 %return.sp, ptr %fiber.sp1, align 8
  %fiber.fp2 = getelementptr inbounds nuw %fiber_control, ptr %fiber_control, i32 0, i32 4
  store i64 %saved.fp, ptr %fiber.fp2, align 8
  ret i32 0

unit.dispatch1:                                   ; preds = %unit.dispatch
  %5 = icmp ult i32 %region, 512, !dbg !46
  br i1 %5, label %unit.test.left, label %unit.test.right, !dbg !46

unit.test.left:                                   ; preds = %unit.dispatch1
  br label %root.prologue

unit.test.right:                                  ; preds = %unit.dispatch1
  br label %entry.yield.resume
}

; Function Attrs: noinline
define i32 @__bpf_capsule_trampoline_step(i32 %fiber, ptr nonnull "bpf.capsule.control" %fiber_control) #2 !dbg !47 {
entry:
  %0 = icmp ne ptr %fiber_control, null, !dbg !51
  br i1 %0, label %control.ready, label %control.missing, !dbg !51

iterate:                                          ; preds = %latch, %control.ready
  %trip = phi i32 [ 0, %control.ready ], [ %trip.next, %latch ], !dbg !51
  %fiber.resume.region.id = getelementptr inbounds nuw %fiber_control, ptr %fiber_control, i32 0, i32 5, !dbg !51
  %resume.region.id = load i32, ptr %fiber.resume.region.id, align 4, !dbg !51
  %1 = icmp eq i32 %resume.region.id, -1, !dbg !51
  %2 = icmp eq i32 %resume.region.id, 0, !dbg !51
  %3 = or i1 %2, %1, !dbg !51
  br label %route, !dbg !51

control.ready:                                    ; preds = %entry
  br label %iterate, !dbg !51

control.missing:                                  ; preds = %entry
  ret i32 1, !dbg !51

route:                                            ; preds = %iterate
  br label %dispatch, !dbg !51

dispatch:                                         ; preds = %route
  %step.index = and i32 %resume.region.id, 255, !dbg !51
  %region.key = and i32 %resume.region.id, 16776960, !dbg !51
  switch i32 %step.index, label %bad.id [
    i32 0, label %idle.or.root
    i32 255, label %completed
  ], !dbg !51

idle.or.root:                                     ; preds = %dispatch
  br i1 %2, label %done, label %bpf.dispatch.output.scalar.0, !dbg !51

bpf.dispatch.output.scalar.0:                     ; preds = %idle.or.root
  %4 = call i32 @bpf.dispatch.output.scalar.0(i32 %fiber, ptr %fiber_control, i32 %region.key), !dbg !51
  %5 = icmp ne i32 %4, 0, !dbg !51
  br i1 %5, label %bpf.dispatch.output.scalar.0.stop, label %latch, !dbg !51

bpf.dispatch.output.scalar.0.stop:                ; preds = %bpf.dispatch.output.scalar.0
  ret i32 %4, !dbg !51

terminal:                                         ; No predecessors!
  br i1 %1, label %completed, label %done, !dbg !51

completed:                                        ; preds = %terminal, %dispatch
  store i32 0, ptr %fiber.resume.region.id, align 4, !dbg !51
  br label %done, !dbg !51

done:                                             ; preds = %completed, %terminal, %idle.or.root
  ret i32 1, !dbg !51

bad.id:                                           ; preds = %dispatch
  %6 = call i32 @bpf_capsule_set_outcome(i32 %fiber, i64 -38654705661), !dbg !51
  ret i32 1, !dbg !51

latch:                                            ; preds = %bpf.dispatch.output.scalar.0
  %trip.next = add i32 %trip, 1, !dbg !51
  %7 = icmp ult i32 %trip.next, 32, !dbg !51
  br i1 %7, label %iterate, label %exhausted, !dbg !51

exhausted:                                        ; preds = %latch
  ret i32 0, !dbg !51
}

; Function Attrs: noinline
define i32 @bpf.dispatch.output.scalar.0(i32 %fiber, ptr nonnull "bpf.capsule.control" %fiber_control, i32 %region) #1 !dbg !52 !bpf.capsule.flatten.root !45 {
entry:
  %0 = icmp ne ptr %fiber_control, null, !dbg !57
  br i1 %0, label %dispatch, label %bad.id, !dbg !57

dispatch:                                         ; preds = %entry
  br label %unit.route, !dbg !57

unit.route:                                       ; preds = %dispatch
  br label %bpf.unit.0, !dbg !57

bad.id:                                           ; preds = %entry
  %1 = call i32 @bpf_capsule_set_outcome(i32 %fiber, i64 -38654705661), !dbg !57
  ret i32 1, !dbg !57

bpf.unit.0:                                       ; preds = %unit.route
  %2 = call i32 @bpf.unit.0(i32 %fiber, ptr %fiber_control, i32 %region), !dbg !57
  ret i32 %2, !dbg !57
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
!18 = !DILocalVariable(name: "control", arg: 2, scope: !6, file: !2, type: !11, annotations: !19)
!19 = !{!20}
!20 = !{!"btf_decl_tag", !"arg:nonnull"}
!21 = !DILocation(line: 0, scope: !6)
!22 = distinct !DISubprogram(name: "__bpf_runtime_glue", linkageName: "__bpf_runtime_glue", scope: null, file: !2, type: !23, spFlags: DISPFlagLocalToUnit | DISPFlagDefinition, unit: !1, retainedNodes: !26)
!23 = !DISubroutineType(types: !24)
!24 = !{!25, !9}
!25 = !DIBasicType(name: "long long", size: 64, encoding: DW_ATE_signed)
!26 = !{!27}
!27 = !DILocalVariable(name: "a0", arg: 1, scope: !22, file: !2, type: !9)
!28 = !DILocation(line: 0, scope: !22)
!29 = !{}
!30 = distinct !DISubprogram(name: "bpf_capsule_set_outcome", linkageName: "bpf_capsule_set_outcome", scope: null, file: !2, type: !31, spFlags: DISPFlagDefinition, unit: !1, retainedNodes: !33)
!31 = !DISubroutineType(types: !32)
!32 = !{!9, !9, !25}
!33 = !{!34, !35}
!34 = !DILocalVariable(name: "a0", arg: 1, scope: !30, file: !2, type: !9)
!35 = !DILocalVariable(name: "a1", arg: 2, scope: !30, file: !2, type: !25)
!36 = !DILocation(line: 0, scope: !30)
!37 = distinct !DISubprogram(name: "bpf.unit.0", linkageName: "bpf.unit.0", scope: null, file: !2, type: !38, flags: DIFlagArtificial, spFlags: DISPFlagDefinition, unit: !1, retainedNodes: !40)
!38 = !DISubroutineType(types: !39)
!39 = !{!9, !10, !11, !10}
!40 = !{!41, !42, !43}
!41 = !DILocalVariable(name: "fiber", arg: 1, scope: !37, file: !2, type: !10)
!42 = !DILocalVariable(name: "fiber_control", arg: 2, scope: !37, file: !2, type: !11)
!43 = !DILocalVariable(name: "region", arg: 3, scope: !37, file: !2, type: !10)
!44 = !{i32 0}
!45 = !{i32 2}
!46 = !DILocation(line: 0, scope: !37)
!47 = distinct !DISubprogram(name: "__bpf_capsule_trampoline_step", linkageName: "__bpf_capsule_trampoline_step", scope: null, file: !2, type: !7, spFlags: DISPFlagDefinition, unit: !1, retainedNodes: !48)
!48 = !{!49, !50}
!49 = !DILocalVariable(name: "fiber", arg: 1, scope: !47, file: !2, type: !10)
!50 = !DILocalVariable(name: "fiber_control", arg: 2, scope: !47, file: !2, type: !11, annotations: !19)
!51 = !DILocation(line: 0, scope: !47)
!52 = distinct !DISubprogram(name: "bpf.dispatch.output.scalar.0", linkageName: "bpf.dispatch.output.scalar.0", scope: null, file: !2, type: !38, spFlags: DISPFlagDefinition, unit: !1, retainedNodes: !53)
!53 = !{!54, !55, !56}
!54 = !DILocalVariable(name: "fiber", arg: 1, scope: !52, file: !2, type: !10)
!55 = !DILocalVariable(name: "fiber_control", arg: 2, scope: !52, file: !2, type: !11, annotations: !19)
!56 = !DILocalVariable(name: "region", arg: 3, scope: !52, file: !2, type: !10)
!57 = !DILocation(line: 0, scope: !52)
