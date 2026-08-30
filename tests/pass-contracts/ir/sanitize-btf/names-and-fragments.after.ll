source_filename = "sanitize-btf.ll"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpfel"

%record = type { i32 }

@named_global = global %record zeroinitializer, align 4, !dbg !0
@split_fragment = global i32 0, align 4

define i32 @named_function(ptr %value) !dbg !14 {
entry:
  ret i32 0
}

!llvm.dbg.cu = !{!2}
!llvm.module.flags = !{!12, !13}

!0 = !DIGlobalVariableExpression(var: !1, expr: !DIExpression())
!1 = distinct !DIGlobalVariable(name: "global__record", scope: !2, file: !3, line: 1, type: !8, isLocal: false, isDefinition: true)
!2 = distinct !DICompileUnit(language: DW_LANG_C11, file: !3, producer: "pass contract", isOptimized: false, runtimeVersion: 0, emissionKind: FullDebug, globals: !4, splitDebugInlining: false, nameTableKind: None)
!3 = !DIFile(filename: "sanitize-btf.c", directory: "/")
!4 = !{!0, !5}
!5 = !DIGlobalVariableExpression(var: !6, expr: !DIExpression(DW_OP_LLVM_fragment, 0, 32))
!6 = distinct !DIGlobalVariable(name: "split__global", scope: !2, file: !3, line: 2, type: !7, isLocal: false, isDefinition: true)
!7 = !DIBasicType(name: "long", size: 64, encoding: DW_ATE_signed)
!8 = distinct !DICompositeType(tag: DW_TAG_structure_type, name: "rust__record_T_", file: !3, line: 1, size: 32, elements: !9)
!9 = !{!10}
!10 = !DIDerivedType(tag: DW_TAG_member, name: "bad_member", scope: !8, file: !3, line: 1, baseType: !11, size: 32)
!11 = !DIBasicType(name: "int", size: 32, encoding: DW_ATE_signed)
!12 = !{i32 7, !"Dwarf Version", i32 5}
!13 = !{i32 2, !"Debug Info Version", i32 3}
!14 = distinct !DISubprogram(name: "call_record_", scope: !3, file: !3, line: 3, type: !15, scopeLine: 3, spFlags: DISPFlagDefinition, unit: !2)
!15 = !DISubroutineType(types: !16)
!16 = !{!11}
