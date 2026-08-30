source_filename = "memory-fixed-stack-contract.c"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpfel"

%config = type { i32, i32, i32, i32, i32, i32, i32, i32, i32, i32, i32, i32, i64 }
%map = type { ptr }

@bpf_capsule_config = constant %config { i32 4096, i32 4096, i32 4194304, i32 4198400, i32 1, i32 4096, i32 1, i32 0, i32 0, i32 0, i32 1112556353, i32 5, i64 0 }, section ".rodata.bpfconfig", align 4
@bpf_heap_array = global %map zeroinitializer, section ".maps", align 8, !dbg !0
@heap0 = global [2097160 x i8] zeroinitializer, section ".bss.heap0", align 8, !dbg !5
@heap1 = global [2097160 x i8] zeroinitializer, section ".bss.heap1", align 8, !dbg !11

define ptr @resolve_stack(i32 %fiber) {
entry:
  %bpf.stack.region.key = alloca i32, align 4, !bpf.native.alloca !23
  %stack.fiber = and i32 %fiber, 0
  %stack.base32 = load volatile i32, ptr getelementptr inbounds nuw (%config, ptr @bpf_capsule_config, i32 0, i32 2), align 4
  %stack.base = zext i32 %stack.base32 to i64
  %0 = zext i32 %stack.fiber to i64
  %1 = mul i64 %0, 4096
  %stack.address = add i64 %stack.base, %1
  %2 = lshr i64 %stack.address, 21
  %stack.region = trunc i64 %2 to i32
  %stack.array.index = sub i32 %stack.region, 2
  store i32 %stack.array.index, ptr %bpf.stack.region.key, align 4
  %bpf.heap.array.value = call ptr inttoptr (i64 1 to ptr)(ptr @bpf_heap_array, ptr %bpf.stack.region.key)
  ret ptr %bpf.heap.array.value
}

define i32 @read_frame(i32 %sp, ptr "bpf.capsule.stack.backing" %stack_base) {
entry:
  %bpf.stack.base.offset32 = load volatile i32, ptr getelementptr inbounds nuw (%config, ptr @bpf_capsule_config, i32 0, i32 2), align 4
  %bpf.stack.base.offset = zext i32 %bpf.stack.base.offset32 to i64
  %bpf.view.base = load volatile i64, ptr getelementptr inbounds nuw (%config, ptr @bpf_capsule_config, i32 0, i32 12), align 8
  %bpf.stack.address = add i64 %bpf.view.base, %bpf.stack.base.offset
  %bpf.stack.base.pointer = inttoptr i64 %bpf.stack.address to ptr
  %wide = zext i32 %sp to i64
  %offset = and i64 %wide, 4095
  %frame = getelementptr i8, ptr %bpf.stack.base.pointer, i64 %offset
  call void asm sideeffect "# bpf_capsule_stack_anchor", "r"(ptr %stack_base)
  %0 = add i64 %offset, 8
  %bpf.stack.offset.visible = call i64 asm sideeffect "", "=r,0"(i64 %0)
  %1 = trunc i64 %bpf.stack.offset.visible to i32
  %2 = and i32 %1, 4095
  %bpf.stack.low.visible = call i32 asm sideeffect "", "=r,0"(i32 %2)
  %3 = icmp ule i32 %bpf.stack.low.visible, 4092
  %bpf.stack.low.bounded = select i1 %3, i32 %bpf.stack.low.visible, i32 0
  %4 = zext i32 %bpf.stack.low.bounded to i64
  %bpf.stack.native = getelementptr i8, ptr %stack_base, i64 %4
  %field = getelementptr i8, ptr %frame, i64 8
  %value = load i32, ptr %bpf.stack.native, align 4
  ret i32 %value
}

define i32 @read_flattened_frame(i32 %sp, ptr "bpf.capsule.control" %fiber_control, ptr "bpf.capsule.stack.backing" %stack_base) !bpf.capsule.flatten.unit !23 {
entry:
  %bpf.stack.base.offset32 = load volatile i32, ptr getelementptr inbounds nuw (%config, ptr @bpf_capsule_config, i32 0, i32 2), align 4
  %bpf.stack.base.offset = zext i32 %bpf.stack.base.offset32 to i64
  %bpf.view.base = load volatile i64, ptr getelementptr inbounds nuw (%config, ptr @bpf_capsule_config, i32 0, i32 12), align 8
  %bpf.stack.address = add i64 %bpf.view.base, %bpf.stack.base.offset
  %bpf.stack.base.pointer = inttoptr i64 %bpf.stack.address to ptr
  %wide = zext i32 %sp to i64
  %offset = and i64 %wide, 4095
  %frame = getelementptr i8, ptr %bpf.stack.base.pointer, i64 %offset
  call void asm sideeffect "# bpf_capsule_stack_anchor", "r"(ptr %stack_base)
  %0 = add i64 %offset, 8
  %bpf.stack.offset.visible = call i64 asm sideeffect "", "=r,0"(i64 %0)
  %1 = trunc i64 %bpf.stack.offset.visible to i32
  %2 = and i32 %1, 4095
  %bpf.stack.low.visible = call i32 asm sideeffect "", "=r,0"(i32 %2)
  %3 = icmp ule i32 %bpf.stack.low.visible, 4092
  br i1 %3, label %bpf.stack.valid, label %bpf.stack.invalid

bpf.stack.invalid:                                ; preds = %entry
  %4 = call i32 @__bpf_capsule_stack_fault(ptr %fiber_control)
  ret i32 %4

bpf.stack.valid:                                  ; preds = %entry
  %5 = zext i32 %bpf.stack.low.visible to i64
  %bpf.stack.native = getelementptr i8, ptr %stack_base, i64 %5
  %field = getelementptr i8, ptr %frame, i64 8
  %value = load i32, ptr %bpf.stack.native, align 4
  ret i32 %value
}

; Function Attrs: nocallback nofree nosync nounwind willreturn memory(argmem: readwrite)
declare void @llvm.lifetime.start.p0(ptr captures(none)) #0

; Function Attrs: nocallback nofree nosync nounwind willreturn memory(argmem: readwrite)
declare void @llvm.lifetime.end.p0(ptr captures(none)) #0

; Function Attrs: noinline
define internal i32 @__bpf_capsule_stack_fault(ptr "bpf.capsule.control" %fiber_control) #1 !dbg !24 {
entry:
  %0 = icmp ne ptr %fiber_control, null, !dbg !34
  br i1 %0, label %publish, label %done, !dbg !34

publish:                                          ; preds = %entry
  store i64 -34359738365, ptr %fiber_control, align 8, !dbg !34
  br label %done, !dbg !34

done:                                             ; preds = %publish, %entry
  ret i32 0, !dbg !34
}

attributes #0 = { nocallback nofree nosync nounwind willreturn memory(argmem: readwrite) }
attributes #1 = { noinline }

!llvm.dbg.cu = !{!2}
!llvm.module.flags = !{!21, !22}

!0 = !DIGlobalVariableExpression(var: !1, expr: !DIExpression())
!1 = distinct !DIGlobalVariable(name: "bpf_heap_array", scope: !2, file: !3, line: 1, type: !13, isLocal: false, isDefinition: true)
!2 = distinct !DICompileUnit(language: DW_LANG_C11, file: !3, producer: "pass contract", isOptimized: false, runtimeVersion: 0, emissionKind: FullDebug, globals: !4)
!3 = !DIFile(filename: "memory-fixed-stack-contract.c", directory: ".")
!4 = !{!0, !5, !11}
!5 = !DIGlobalVariableExpression(var: !6, expr: !DIExpression())
!6 = distinct !DIGlobalVariable(name: "heap0", linkageName: "heap0", scope: !2, file: !3, type: !7, isLocal: true, isDefinition: true)
!7 = !DICompositeType(tag: DW_TAG_array_type, baseType: !8, size: 16777280, align: 8, elements: !9)
!8 = !DIBasicType(name: "char", size: 8, encoding: DW_ATE_signed_char)
!9 = !{!10}
!10 = !DISubrange(count: 2097160, lowerBound: 0)
!11 = !DIGlobalVariableExpression(var: !12, expr: !DIExpression())
!12 = distinct !DIGlobalVariable(name: "heap1", linkageName: "heap1", scope: !2, file: !3, type: !7, isLocal: true, isDefinition: true)
!13 = distinct !DICompositeType(tag: DW_TAG_structure_type, name: "heap_array_map", file: !3, line: 1, size: 64, elements: !14)
!14 = !{!15}
!15 = !DIDerivedType(tag: DW_TAG_member, name: "max_entries", scope: !13, file: !3, line: 1, baseType: !16, size: 64)
!16 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !17, size: 64)
!17 = !DICompositeType(tag: DW_TAG_array_type, baseType: !18, size: 32, elements: !19)
!18 = !DIBasicType(name: "int", size: 32, encoding: DW_ATE_signed)
!19 = !{!20}
!20 = !DISubrange(count: 1, lowerBound: 0)
!21 = !{i32 2, !"Dwarf Version", i32 4}
!22 = !{i32 2, !"Debug Info Version", i32 3}
!23 = !{}
!24 = distinct !DISubprogram(name: "__bpf_capsule_stack_fault", linkageName: "__bpf_capsule_stack_fault", scope: null, file: !3, type: !25, spFlags: DISPFlagDefinition, unit: !2, retainedNodes: !32)
!25 = !DISubroutineType(types: !26)
!26 = !{!18, !27}
!27 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !28, size: 64)
!28 = !DICompositeType(tag: DW_TAG_array_type, baseType: !29, size: 320, align: 8, elements: !30)
!29 = !DIBasicType(name: "unsigned char", size: 8, encoding: DW_ATE_unsigned_char)
!30 = !{!31}
!31 = !DISubrange(count: 40, lowerBound: 0)
!32 = !{!33}
!33 = !DILocalVariable(name: "fiber_control", arg: 1, scope: !24, file: !3, type: !27)
!34 = !DILocation(line: 0, scope: !24)
