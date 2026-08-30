source_filename = "memory-fixed-contract.c"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpfel"

%config = type { i32, i32, i32, i32, i32, i32, i32, i32, i32, i32, i32, i32, i64 }
%map = type { ptr }

@bpf_capsule_config = constant %config { i32 4112, i32 4096, i32 67108864, i32 67112960, i32 1, i32 4096, i32 1, i32 0, i32 0, i32 0, i32 1112556353, i32 5, i64 0 }, section ".rodata.bpfconfig", align 4
@bpf_heap_array = global %map zeroinitializer, section ".maps", align 8, !dbg !0
@heap0 = global [2097160 x i8] zeroinitializer, section ".bss.heap0", align 8, !dbg !5
@heap1 = global [2097160 x i8] zeroinitializer, section ".bss.heap1", align 8, !dbg !11
@heap2 = global [2097160 x i8] zeroinitializer, section ".bss.heap2", align 8, !dbg !13
@heap3 = global [2097160 x i8] zeroinitializer, section ".bss.heap3", align 8, !dbg !15
@heap4 = global [2097160 x i8] zeroinitializer, section ".bss.heap4", align 8, !dbg !17
@heap5 = global [2097160 x i8] zeroinitializer, section ".bss.heap5", align 8, !dbg !19
@heap6 = global [2097160 x i8] zeroinitializer, section ".bss.heap6", align 8, !dbg !21
@heap7 = global [2097160 x i8] zeroinitializer, section ".bss.heap7", align 8, !dbg !23
@heap8 = global [2097160 x i8] zeroinitializer, section ".bss.heap8", align 8, !dbg !25
@heap9 = global [2097160 x i8] zeroinitializer, section ".bss.heap9", align 8, !dbg !27
@heap10 = global [2097160 x i8] zeroinitializer, section ".bss.heap10", align 8, !dbg !29
@heap11 = global [2097160 x i8] zeroinitializer, section ".bss.heap11", align 8, !dbg !31
@heap12 = global [2097160 x i8] zeroinitializer, section ".bss.heap12", align 8, !dbg !33
@heap13 = global [2097160 x i8] zeroinitializer, section ".bss.heap13", align 8, !dbg !35
@heap14 = global [2097160 x i8] zeroinitializer, section ".bss.heap14", align 8, !dbg !37
@heap15 = global [2097160 x i8] zeroinitializer, section ".bss.heap15", align 8, !dbg !39
@heap16 = global [2097160 x i8] zeroinitializer, section ".bss.heap16", align 8, !dbg !41
@heap17 = global [2097160 x i8] zeroinitializer, section ".bss.heap17", align 8, !dbg !43
@heap18 = global [2097160 x i8] zeroinitializer, section ".bss.heap18", align 8, !dbg !45
@heap19 = global [2097160 x i8] zeroinitializer, section ".bss.heap19", align 8, !dbg !47
@heap20 = global [2097160 x i8] zeroinitializer, section ".bss.heap20", align 8, !dbg !49
@heap21 = global [2097160 x i8] zeroinitializer, section ".bss.heap21", align 8, !dbg !51
@heap22 = global [2097160 x i8] zeroinitializer, section ".bss.heap22", align 8, !dbg !53
@heap23 = global [2097160 x i8] zeroinitializer, section ".bss.heap23", align 8, !dbg !55
@heap24 = global [2097160 x i8] zeroinitializer, section ".bss.heap24", align 8, !dbg !57
@heap25 = global [2097160 x i8] zeroinitializer, section ".bss.heap25", align 8, !dbg !59
@heap26 = global [2097160 x i8] zeroinitializer, section ".bss.heap26", align 8, !dbg !61
@heap27 = global [2097160 x i8] zeroinitializer, section ".bss.heap27", align 8, !dbg !63
@heap28 = global [2097160 x i8] zeroinitializer, section ".bss.heap28", align 8, !dbg !65
@heap29 = global [2097160 x i8] zeroinitializer, section ".bss.heap29", align 8, !dbg !67
@heap30 = global [2097160 x i8] zeroinitializer, section ".bss.heap30", align 8, !dbg !69
@heap31 = global [2097160 x i8] zeroinitializer, section ".bss.heap31", align 8, !dbg !71

define i8 @read(i64 %index) {
entry:
  %bpf.view.base = load volatile i64, ptr getelementptr inbounds nuw (%config, ptr @bpf_capsule_config, i32 0, i32 12), align 8
  %sparse.addr = add i64 %bpf.view.base, 4096
  %sparse.ptr = inttoptr i64 %sparse.addr to ptr
  %slot = getelementptr [16 x i8], ptr %sparse.ptr, i64 0, i64 %index
  %0 = ptrtoint ptr %slot to i64
  %bpf.map.offset.visible = call i64 asm sideeffect "", "=r,0"(i64 %0)
  %1 = trunc i64 %bpf.map.offset.visible to i32
  %2 = and i32 %1, 2097151
  %3 = zext i32 %2 to i64
  %4 = getelementptr i8, ptr @heap0, i64 %3
  %byte = load i8, ptr %4, align 1
  ret i8 %byte
}

; Function Attrs: nocallback nofree nosync nounwind willreturn memory(argmem: readwrite)
declare void @llvm.lifetime.start.p0(ptr captures(none)) #0

; Function Attrs: nocallback nofree nosync nounwind willreturn memory(argmem: readwrite)
declare void @llvm.lifetime.end.p0(ptr captures(none)) #0

attributes #0 = { nocallback nofree nosync nounwind willreturn memory(argmem: readwrite) }

!llvm.dbg.cu = !{!2}
!llvm.module.flags = !{!81, !82}

!0 = !DIGlobalVariableExpression(var: !1, expr: !DIExpression())
!1 = distinct !DIGlobalVariable(name: "bpf_heap_array", scope: !2, file: !3, line: 1, type: !73, isLocal: false, isDefinition: true)
!2 = distinct !DICompileUnit(language: DW_LANG_C11, file: !3, producer: "pass contract", isOptimized: false, runtimeVersion: 0, emissionKind: FullDebug, globals: !4)
!3 = !DIFile(filename: "memory-fixed-contract.c", directory: ".")
!4 = !{!0, !5, !11, !13, !15, !17, !19, !21, !23, !25, !27, !29, !31, !33, !35, !37, !39, !41, !43, !45, !47, !49, !51, !53, !55, !57, !59, !61, !63, !65, !67, !69, !71}
!5 = !DIGlobalVariableExpression(var: !6, expr: !DIExpression())
!6 = distinct !DIGlobalVariable(name: "heap0", linkageName: "heap0", scope: !2, file: !3, type: !7, isLocal: true, isDefinition: true)
!7 = !DICompositeType(tag: DW_TAG_array_type, baseType: !8, size: 16777280, align: 8, elements: !9)
!8 = !DIBasicType(name: "char", size: 8, encoding: DW_ATE_signed_char)
!9 = !{!10}
!10 = !DISubrange(count: 2097160, lowerBound: 0)
!11 = !DIGlobalVariableExpression(var: !12, expr: !DIExpression())
!12 = distinct !DIGlobalVariable(name: "heap1", linkageName: "heap1", scope: !2, file: !3, type: !7, isLocal: true, isDefinition: true)
!13 = !DIGlobalVariableExpression(var: !14, expr: !DIExpression())
!14 = distinct !DIGlobalVariable(name: "heap2", linkageName: "heap2", scope: !2, file: !3, type: !7, isLocal: true, isDefinition: true)
!15 = !DIGlobalVariableExpression(var: !16, expr: !DIExpression())
!16 = distinct !DIGlobalVariable(name: "heap3", linkageName: "heap3", scope: !2, file: !3, type: !7, isLocal: true, isDefinition: true)
!17 = !DIGlobalVariableExpression(var: !18, expr: !DIExpression())
!18 = distinct !DIGlobalVariable(name: "heap4", linkageName: "heap4", scope: !2, file: !3, type: !7, isLocal: true, isDefinition: true)
!19 = !DIGlobalVariableExpression(var: !20, expr: !DIExpression())
!20 = distinct !DIGlobalVariable(name: "heap5", linkageName: "heap5", scope: !2, file: !3, type: !7, isLocal: true, isDefinition: true)
!21 = !DIGlobalVariableExpression(var: !22, expr: !DIExpression())
!22 = distinct !DIGlobalVariable(name: "heap6", linkageName: "heap6", scope: !2, file: !3, type: !7, isLocal: true, isDefinition: true)
!23 = !DIGlobalVariableExpression(var: !24, expr: !DIExpression())
!24 = distinct !DIGlobalVariable(name: "heap7", linkageName: "heap7", scope: !2, file: !3, type: !7, isLocal: true, isDefinition: true)
!25 = !DIGlobalVariableExpression(var: !26, expr: !DIExpression())
!26 = distinct !DIGlobalVariable(name: "heap8", linkageName: "heap8", scope: !2, file: !3, type: !7, isLocal: true, isDefinition: true)
!27 = !DIGlobalVariableExpression(var: !28, expr: !DIExpression())
!28 = distinct !DIGlobalVariable(name: "heap9", linkageName: "heap9", scope: !2, file: !3, type: !7, isLocal: true, isDefinition: true)
!29 = !DIGlobalVariableExpression(var: !30, expr: !DIExpression())
!30 = distinct !DIGlobalVariable(name: "heap10", linkageName: "heap10", scope: !2, file: !3, type: !7, isLocal: true, isDefinition: true)
!31 = !DIGlobalVariableExpression(var: !32, expr: !DIExpression())
!32 = distinct !DIGlobalVariable(name: "heap11", linkageName: "heap11", scope: !2, file: !3, type: !7, isLocal: true, isDefinition: true)
!33 = !DIGlobalVariableExpression(var: !34, expr: !DIExpression())
!34 = distinct !DIGlobalVariable(name: "heap12", linkageName: "heap12", scope: !2, file: !3, type: !7, isLocal: true, isDefinition: true)
!35 = !DIGlobalVariableExpression(var: !36, expr: !DIExpression())
!36 = distinct !DIGlobalVariable(name: "heap13", linkageName: "heap13", scope: !2, file: !3, type: !7, isLocal: true, isDefinition: true)
!37 = !DIGlobalVariableExpression(var: !38, expr: !DIExpression())
!38 = distinct !DIGlobalVariable(name: "heap14", linkageName: "heap14", scope: !2, file: !3, type: !7, isLocal: true, isDefinition: true)
!39 = !DIGlobalVariableExpression(var: !40, expr: !DIExpression())
!40 = distinct !DIGlobalVariable(name: "heap15", linkageName: "heap15", scope: !2, file: !3, type: !7, isLocal: true, isDefinition: true)
!41 = !DIGlobalVariableExpression(var: !42, expr: !DIExpression())
!42 = distinct !DIGlobalVariable(name: "heap16", linkageName: "heap16", scope: !2, file: !3, type: !7, isLocal: true, isDefinition: true)
!43 = !DIGlobalVariableExpression(var: !44, expr: !DIExpression())
!44 = distinct !DIGlobalVariable(name: "heap17", linkageName: "heap17", scope: !2, file: !3, type: !7, isLocal: true, isDefinition: true)
!45 = !DIGlobalVariableExpression(var: !46, expr: !DIExpression())
!46 = distinct !DIGlobalVariable(name: "heap18", linkageName: "heap18", scope: !2, file: !3, type: !7, isLocal: true, isDefinition: true)
!47 = !DIGlobalVariableExpression(var: !48, expr: !DIExpression())
!48 = distinct !DIGlobalVariable(name: "heap19", linkageName: "heap19", scope: !2, file: !3, type: !7, isLocal: true, isDefinition: true)
!49 = !DIGlobalVariableExpression(var: !50, expr: !DIExpression())
!50 = distinct !DIGlobalVariable(name: "heap20", linkageName: "heap20", scope: !2, file: !3, type: !7, isLocal: true, isDefinition: true)
!51 = !DIGlobalVariableExpression(var: !52, expr: !DIExpression())
!52 = distinct !DIGlobalVariable(name: "heap21", linkageName: "heap21", scope: !2, file: !3, type: !7, isLocal: true, isDefinition: true)
!53 = !DIGlobalVariableExpression(var: !54, expr: !DIExpression())
!54 = distinct !DIGlobalVariable(name: "heap22", linkageName: "heap22", scope: !2, file: !3, type: !7, isLocal: true, isDefinition: true)
!55 = !DIGlobalVariableExpression(var: !56, expr: !DIExpression())
!56 = distinct !DIGlobalVariable(name: "heap23", linkageName: "heap23", scope: !2, file: !3, type: !7, isLocal: true, isDefinition: true)
!57 = !DIGlobalVariableExpression(var: !58, expr: !DIExpression())
!58 = distinct !DIGlobalVariable(name: "heap24", linkageName: "heap24", scope: !2, file: !3, type: !7, isLocal: true, isDefinition: true)
!59 = !DIGlobalVariableExpression(var: !60, expr: !DIExpression())
!60 = distinct !DIGlobalVariable(name: "heap25", linkageName: "heap25", scope: !2, file: !3, type: !7, isLocal: true, isDefinition: true)
!61 = !DIGlobalVariableExpression(var: !62, expr: !DIExpression())
!62 = distinct !DIGlobalVariable(name: "heap26", linkageName: "heap26", scope: !2, file: !3, type: !7, isLocal: true, isDefinition: true)
!63 = !DIGlobalVariableExpression(var: !64, expr: !DIExpression())
!64 = distinct !DIGlobalVariable(name: "heap27", linkageName: "heap27", scope: !2, file: !3, type: !7, isLocal: true, isDefinition: true)
!65 = !DIGlobalVariableExpression(var: !66, expr: !DIExpression())
!66 = distinct !DIGlobalVariable(name: "heap28", linkageName: "heap28", scope: !2, file: !3, type: !7, isLocal: true, isDefinition: true)
!67 = !DIGlobalVariableExpression(var: !68, expr: !DIExpression())
!68 = distinct !DIGlobalVariable(name: "heap29", linkageName: "heap29", scope: !2, file: !3, type: !7, isLocal: true, isDefinition: true)
!69 = !DIGlobalVariableExpression(var: !70, expr: !DIExpression())
!70 = distinct !DIGlobalVariable(name: "heap30", linkageName: "heap30", scope: !2, file: !3, type: !7, isLocal: true, isDefinition: true)
!71 = !DIGlobalVariableExpression(var: !72, expr: !DIExpression())
!72 = distinct !DIGlobalVariable(name: "heap31", linkageName: "heap31", scope: !2, file: !3, type: !7, isLocal: true, isDefinition: true)
!73 = distinct !DICompositeType(tag: DW_TAG_structure_type, name: "heap_array_map", file: !3, line: 1, size: 64, elements: !74)
!74 = !{!75}
!75 = !DIDerivedType(tag: DW_TAG_member, name: "max_entries", scope: !73, file: !3, line: 1, baseType: !76, size: 64)
!76 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !77, size: 64)
!77 = !DICompositeType(tag: DW_TAG_array_type, baseType: !78, size: 32, elements: !79)
!78 = !DIBasicType(name: "int", size: 32, encoding: DW_ATE_signed)
!79 = !{!80}
!80 = !DISubrange(count: 1, lowerBound: 0)
!81 = !{i32 2, !"Dwarf Version", i32 4}
!82 = !{i32 2, !"Debug Info Version", i32 3}
