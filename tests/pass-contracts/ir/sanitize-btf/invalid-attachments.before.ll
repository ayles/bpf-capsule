source_filename = "sanitize-btf-invalid-attachments.ll"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpfel"

@fragment = global i32 0, align 4, !dbg !0
@wrong_size = global i32 0, align 4, !dbg !5

!llvm.dbg.cu = !{!2}
!llvm.module.flags = !{!9, !10}

!0 = !DIGlobalVariableExpression(var: !1, expr: !DIExpression(DW_OP_LLVM_fragment, 0, 16))
!1 = distinct !DIGlobalVariable(name: "fragment", scope: !2, file: !3, line: 1, type: !8, isLocal: false, isDefinition: true)
!2 = distinct !DICompileUnit(language: DW_LANG_C11, file: !3, producer: "pass contract", isOptimized: true, runtimeVersion: 0, emissionKind: FullDebug, globals: !4, splitDebugInlining: false, nameTableKind: None)
!3 = !DIFile(filename: "sanitize-btf-invalid-attachments.c", directory: "/")
!4 = !{!0, !5}
!5 = !DIGlobalVariableExpression(var: !6, expr: !DIExpression())
!6 = distinct !DIGlobalVariable(name: "wrong_size", scope: !2, file: !3, line: 2, type: !7, isLocal: false, isDefinition: true)
!7 = !DIBasicType(name: "long", size: 64, encoding: DW_ATE_signed)
!8 = !DIBasicType(name: "int", size: 32, encoding: DW_ATE_signed)
!9 = !{i32 7, !"Dwarf Version", i32 5}
!10 = !{i32 2, !"Debug Info Version", i32 3}
