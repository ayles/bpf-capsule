source_filename = "memory-fixed-accessors-contract.c"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpfel"

%config = type { i32, i32, i32, i32, i32, i32, i32, i32, i32, i32, i32, i32, i64 }
%map = type { ptr }

@bpf_capsule_config = constant %config { i32 4096, i32 4096, i32 4194304, i32 4198400, i32 1, i32 4096, i32 1, i32 0, i32 0, i32 0, i32 1112556353, i32 5, i64 0 }, section ".rodata.bpfconfig", align 4
@bpf_heap_array = global %map zeroinitializer, section ".maps", align 8, !dbg !0
@heap0 = global [2097160 x i8] zeroinitializer, section ".bss.heap0", align 8, !dbg !5
@heap1 = global [2097160 x i8] zeroinitializer, section ".bss.heap1", align 8, !dbg !11

define i32 @read_any(ptr %address) {
entry:
  %0 = ptrtoint ptr %address to i64
  %1 = call i64 @bpf_heap_load32(i64 %0)
  %2 = trunc i64 %1 to i32
  ret i32 %2
}

define void @write_any(ptr %address, i64 %value) {
entry:
  %0 = ptrtoint ptr %address to i64
  %1 = call i32 @bpf_heap_store64(i64 %0, i64 %value)
  ret void
}

; Function Attrs: nocallback nofree nosync nounwind willreturn memory(argmem: readwrite)
declare void @llvm.lifetime.start.p0(ptr captures(none)) #0

; Function Attrs: nocallback nofree nosync nounwind willreturn memory(argmem: readwrite)
declare void @llvm.lifetime.end.p0(ptr captures(none)) #0

; Function Attrs: noinline
define i64 @bpf_heap_load32(i64 %offset) #1 !dbg !23 {
entry:
  %bpf.heap.array.key.i = alloca i32, align 4, !dbg !29, !bpf.native.alloca !34
  %0 = and i64 %offset, 2097151, !dbg !35
  %bpf.heap.offset.visible = call i64 asm sideeffect "", "=r,0"(i64 %0), !dbg !35
  %1 = trunc i64 %offset to i32, !dbg !35
  %2 = lshr i32 %1, 21, !dbg !35
  %3 = icmp eq i32 %2, 0, !dbg !35
  br i1 %3, label %region.0, label %region.route, !dbg !35

array:                                            ; preds = %region.route
  call void @llvm.lifetime.start.p0(ptr %bpf.heap.array.key.i), !dbg !29
  %4 = and i64 %offset, 2097151, !dbg !29
  %bpf.heap.offset.visible.i = call i64 asm sideeffect "", "=r,0"(i64 %4), !dbg !29
  %5 = trunc i64 %offset to i32, !dbg !29
  %6 = lshr i32 %5, 21, !dbg !29
  %7 = icmp uge i32 %6, 2, !dbg !29
  br i1 %7, label %lookup.i, label %invalid.i, !dbg !29

lookup.i:                                         ; preds = %array
  %8 = sub i32 %6, 2, !dbg !29
  store i32 %8, ptr %bpf.heap.array.key.i, align 4, !dbg !29
  %bpf.heap.array.value.i = call ptr inttoptr (i64 1 to ptr)(ptr @bpf_heap_array, ptr %bpf.heap.array.key.i), !dbg !29
  %9 = icmp ne ptr %bpf.heap.array.value.i, null, !dbg !29
  br i1 %9, label %access.i, label %invalid.i, !dbg !29

access.i:                                         ; preds = %lookup.i
  %10 = getelementptr i8, ptr %bpf.heap.array.value.i, i64 %bpf.heap.offset.visible.i, !dbg !29
  %11 = load i32, ptr %10, align 4, !dbg !29
  %12 = zext i32 %11 to i64, !dbg !29
  call void @llvm.lifetime.end.p0(ptr %bpf.heap.array.key.i), !dbg !29
  br label %bpf_heap_array_load32.exit, !dbg !29

invalid.i:                                        ; preds = %lookup.i, %array
  call void @llvm.lifetime.end.p0(ptr %bpf.heap.array.key.i), !dbg !29
  br label %bpf_heap_array_load32.exit, !dbg !29

bpf_heap_array_load32.exit:                       ; preds = %invalid.i, %access.i
  %13 = phi i64 [ %12, %access.i ], [ 0, %invalid.i ]
  ret i64 %13, !dbg !35

region.route:                                     ; preds = %entry
  switch i32 %2, label %array [
    i32 1, label %region.1
  ], !dbg !35

region.0:                                         ; preds = %entry
  %14 = getelementptr i8, ptr @heap0, i64 %bpf.heap.offset.visible, !dbg !35
  %15 = load i32, ptr %14, align 4, !dbg !35
  %16 = zext i32 %15 to i64, !dbg !35
  ret i64 %16, !dbg !35

region.1:                                         ; preds = %region.route
  %17 = getelementptr i8, ptr @heap1, i64 %bpf.heap.offset.visible, !dbg !35
  %18 = load i32, ptr %17, align 4, !dbg !35
  %19 = zext i32 %18 to i64, !dbg !35
  ret i64 %19, !dbg !35

invalid:                                          ; No predecessors!
  ret i64 0, !dbg !35
}

; Function Attrs: noinline
define i32 @bpf_heap_store64(i64 %offset, i64 %value) #1 !dbg !36 {
entry:
  %bpf.heap.array.key.i = alloca i32, align 4, !dbg !42, !bpf.native.alloca !34
  %bpf.heap.array.key = alloca i32, align 4, !dbg !48, !bpf.native.alloca !34
  %0 = and i64 %offset, 2097151, !dbg !48
  %bpf.heap.offset.visible = call i64 asm sideeffect "", "=r,0"(i64 %0), !dbg !48
  %1 = trunc i64 %offset to i32, !dbg !48
  %2 = lshr i32 %1, 21, !dbg !48
  %3 = icmp eq i32 %2, 0, !dbg !48
  br i1 %3, label %region.0, label %region.route, !dbg !48

array:                                            ; preds = %region.route
  call void @llvm.lifetime.start.p0(ptr %bpf.heap.array.key.i), !dbg !42
  %4 = and i64 %offset, 2097151, !dbg !42
  %bpf.heap.offset.visible.i = call i64 asm sideeffect "", "=r,0"(i64 %4), !dbg !42
  %5 = trunc i64 %offset to i32, !dbg !42
  %6 = lshr i32 %5, 21, !dbg !42
  %7 = icmp uge i32 %6, 2, !dbg !42
  br i1 %7, label %lookup.i, label %invalid.i, !dbg !42

lookup.i:                                         ; preds = %array
  %8 = sub i32 %6, 2, !dbg !42
  store i32 %8, ptr %bpf.heap.array.key.i, align 4, !dbg !42
  %bpf.heap.array.value.i = call ptr inttoptr (i64 1 to ptr)(ptr @bpf_heap_array, ptr %bpf.heap.array.key.i), !dbg !42
  %9 = icmp ne ptr %bpf.heap.array.value.i, null, !dbg !42
  br i1 %9, label %access.i, label %invalid.i, !dbg !42

access.i:                                         ; preds = %lookup.i
  %10 = getelementptr i8, ptr %bpf.heap.array.value.i, i64 %bpf.heap.offset.visible.i, !dbg !42
  store i64 %value, ptr %10, align 8, !dbg !42
  %11 = icmp ugt i64 %bpf.heap.offset.visible.i, 2097144, !dbg !42
  %12 = icmp ult i32 %6, 2047, !dbg !42
  %13 = and i1 %11, %12, !dbg !42
  br i1 %13, label %sync.next.i, label %after.next.i, !dbg !42

sync.next.i:                                      ; preds = %access.i
  %14 = getelementptr i8, ptr %bpf.heap.array.value.i, i64 2097152, !dbg !42
  %15 = load i64, ptr %14, align 8, !dbg !42
  %16 = add i32 %8, 1, !dbg !42
  store i32 %16, ptr %bpf.heap.array.key.i, align 4, !dbg !42
  %bpf.heap.array.value1.i = call ptr inttoptr (i64 1 to ptr)(ptr @bpf_heap_array, ptr %bpf.heap.array.key.i), !dbg !42
  %17 = icmp ne ptr %bpf.heap.array.value1.i, null, !dbg !42
  br i1 %17, label %sync.next.write.i, label %invalid.i, !dbg !42

after.next.i:                                     ; preds = %sync.next.write.i, %access.i
  %18 = icmp ult i64 %bpf.heap.offset.visible.i, 8, !dbg !42
  %19 = icmp ugt i32 %6, 0, !dbg !42
  %20 = and i1 %18, %19, !dbg !42
  br i1 %20, label %sync.previous.i, label %done.i, !dbg !42

sync.next.write.i:                                ; preds = %sync.next.i
  store i64 %15, ptr %bpf.heap.array.value1.i, align 8, !dbg !42
  br label %after.next.i, !dbg !42

sync.previous.i:                                  ; preds = %after.next.i
  %21 = load i64, ptr %bpf.heap.array.value.i, align 8, !dbg !42
  %22 = icmp eq i32 %8, 0, !dbg !42
  br i1 %22, label %sync.previous.direct.i, label %sync.previous.paged.i, !dbg !42

done.i:                                           ; preds = %sync.previous.write.i, %sync.previous.direct.i, %after.next.i
  call void @llvm.lifetime.end.p0(ptr %bpf.heap.array.key.i), !dbg !42
  br label %bpf_heap_array_store64.exit, !dbg !42

sync.previous.direct.i:                           ; preds = %sync.previous.i
  store i64 %21, ptr getelementptr (i8, ptr @heap1, i64 2097152), align 8, !dbg !42
  br label %done.i, !dbg !42

sync.previous.paged.i:                            ; preds = %sync.previous.i
  %23 = sub i32 %8, 1, !dbg !42
  store i32 %23, ptr %bpf.heap.array.key.i, align 4, !dbg !42
  %bpf.heap.array.value2.i = call ptr inttoptr (i64 1 to ptr)(ptr @bpf_heap_array, ptr %bpf.heap.array.key.i), !dbg !42
  %24 = icmp ne ptr %bpf.heap.array.value2.i, null, !dbg !42
  br i1 %24, label %sync.previous.write.i, label %invalid.i, !dbg !42

sync.previous.write.i:                            ; preds = %sync.previous.paged.i
  %25 = getelementptr i8, ptr %bpf.heap.array.value2.i, i64 2097152, !dbg !42
  store i64 %21, ptr %25, align 8, !dbg !42
  br label %done.i, !dbg !42

invalid.i:                                        ; preds = %sync.previous.paged.i, %sync.next.i, %lookup.i, %array
  call void @llvm.lifetime.end.p0(ptr %bpf.heap.array.key.i), !dbg !42
  br label %bpf_heap_array_store64.exit, !dbg !42

bpf_heap_array_store64.exit:                      ; preds = %invalid.i, %done.i
  ret i32 0, !dbg !48

region.route:                                     ; preds = %entry
  switch i32 %2, label %array [
    i32 1, label %region.1
  ], !dbg !48

region.0:                                         ; preds = %entry
  %26 = getelementptr i8, ptr @heap0, i64 %bpf.heap.offset.visible, !dbg !48
  store i64 %value, ptr %26, align 8, !dbg !48
  %27 = icmp ugt i64 %bpf.heap.offset.visible, 2097144, !dbg !48
  br i1 %27, label %region.0.sync.next, label %region.0.after.next, !dbg !48

region.0.sync.next:                               ; preds = %region.0
  %28 = load i64, ptr getelementptr (i8, ptr @heap0, i64 2097152), align 8, !dbg !48
  store i64 %28, ptr @heap1, align 8, !dbg !48
  br label %region.0.after.next, !dbg !48

region.0.after.next:                              ; preds = %region.0.sync.next, %region.0
  ret i32 0, !dbg !48

region.1:                                         ; preds = %region.route
  %29 = getelementptr i8, ptr @heap1, i64 %bpf.heap.offset.visible, !dbg !48
  store i64 %value, ptr %29, align 8, !dbg !48
  %30 = icmp ugt i64 %bpf.heap.offset.visible, 2097144, !dbg !48
  br i1 %30, label %region.1.sync.next, label %region.1.after.next, !dbg !48

region.1.sync.next:                               ; preds = %region.1
  %31 = load i64, ptr getelementptr (i8, ptr @heap1, i64 2097152), align 8, !dbg !48
  store i32 0, ptr %bpf.heap.array.key, align 4, !dbg !48
  %bpf.heap.array.value = call ptr inttoptr (i64 1 to ptr)(ptr @bpf_heap_array, ptr %bpf.heap.array.key), !dbg !48
  %32 = icmp ne ptr %bpf.heap.array.value, null, !dbg !48
  br i1 %32, label %region.1.sync.next.write, label %invalid, !dbg !48

region.1.after.next:                              ; preds = %region.1.sync.next.write, %region.1
  %33 = icmp ult i64 %bpf.heap.offset.visible, 8, !dbg !48
  br i1 %33, label %region.1.sync.previous, label %region.1.done, !dbg !48

region.1.sync.next.write:                         ; preds = %region.1.sync.next
  store i64 %31, ptr %bpf.heap.array.value, align 8, !dbg !48
  br label %region.1.after.next, !dbg !48

region.1.sync.previous:                           ; preds = %region.1.after.next
  %34 = load i64, ptr @heap1, align 8, !dbg !48
  store i64 %34, ptr getelementptr (i8, ptr @heap0, i64 2097152), align 8, !dbg !48
  br label %region.1.done, !dbg !48

region.1.done:                                    ; preds = %region.1.sync.previous, %region.1.after.next
  ret i32 0, !dbg !48

invalid:                                          ; preds = %region.1.sync.next
  ret i32 0, !dbg !48
}

attributes #0 = { nocallback nofree nosync nounwind willreturn memory(argmem: readwrite) }
attributes #1 = { noinline "capsule.heap-accessor" }

!llvm.dbg.cu = !{!2}
!llvm.module.flags = !{!21, !22}

!0 = !DIGlobalVariableExpression(var: !1, expr: !DIExpression())
!1 = distinct !DIGlobalVariable(name: "bpf_heap_array", scope: !2, file: !3, line: 1, type: !13, isLocal: false, isDefinition: true)
!2 = distinct !DICompileUnit(language: DW_LANG_C11, file: !3, producer: "pass contract", isOptimized: false, runtimeVersion: 0, emissionKind: FullDebug, globals: !4)
!3 = !DIFile(filename: "memory-fixed-accessors-contract.c", directory: ".")
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
!23 = distinct !DISubprogram(name: "bpf_heap_load32", linkageName: "bpf_heap_load32", scope: null, file: !3, type: !24, spFlags: DISPFlagDefinition, unit: !2, retainedNodes: !27)
!24 = !DISubroutineType(types: !25)
!25 = !{!26, !26}
!26 = !DIBasicType(name: "unsigned long long", size: 64, encoding: DW_ATE_unsigned)
!27 = !{!28}
!28 = !DILocalVariable(name: "offset", arg: 1, scope: !23, file: !3, type: !26)
!29 = !DILocation(line: 0, scope: !30, inlinedAt: !33)
!30 = distinct !DISubprogram(name: "bpf_heap_array_load32", linkageName: "bpf_heap_array_load32", scope: null, file: !3, type: !24, spFlags: DISPFlagDefinition, unit: !2, retainedNodes: !31)
!31 = !{!32}
!32 = !DILocalVariable(name: "offset", arg: 1, scope: !30, file: !3, type: !26)
!33 = distinct !DILocation(line: 0, scope: !23)
!34 = !{}
!35 = !DILocation(line: 0, scope: !23)
!36 = distinct !DISubprogram(name: "bpf_heap_store64", linkageName: "bpf_heap_store64", scope: null, file: !3, type: !37, spFlags: DISPFlagDefinition, unit: !2, retainedNodes: !39)
!37 = !DISubroutineType(types: !38)
!38 = !{!18, !26, !26}
!39 = !{!40, !41}
!40 = !DILocalVariable(name: "offset", arg: 1, scope: !36, file: !3, type: !26)
!41 = !DILocalVariable(name: "value", arg: 2, scope: !36, file: !3, type: !26)
!42 = !DILocation(line: 0, scope: !43, inlinedAt: !47)
!43 = distinct !DISubprogram(name: "bpf_heap_array_store64", linkageName: "bpf_heap_array_store64", scope: null, file: !3, type: !37, spFlags: DISPFlagDefinition, unit: !2, retainedNodes: !44)
!44 = !{!45, !46}
!45 = !DILocalVariable(name: "offset", arg: 1, scope: !43, file: !3, type: !26)
!46 = !DILocalVariable(name: "value", arg: 2, scope: !43, file: !3, type: !26)
!47 = distinct !DILocation(line: 0, scope: !36)
!48 = !DILocation(line: 0, scope: !36)
