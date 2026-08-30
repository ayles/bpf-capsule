source_filename = "sanitize-btf-invalid-attachments.ll"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpfel"

@fragment = global i32 0, align 4
@wrong_size = global i32 0, align 4

!llvm.dbg.cu = !{!0}
!llvm.module.flags = !{!9, !10}

!0 = distinct !DICompileUnit(language: DW_LANG_C11, file: !1, producer: "pass contract", isOptimized: true, runtimeVersion: 0, emissionKind: FullDebug, globals: !2, splitDebugInlining: false, nameTableKind: None)
!1 = !DIFile(filename: "sanitize-btf-invalid-attachments.c", directory: "/")
!2 = !{!3, !6}
!3 = !DIGlobalVariableExpression(var: !4, expr: !DIExpression(DW_OP_LLVM_fragment, 0, 16))
!4 = distinct !DIGlobalVariable(name: "fragment", scope: !0, file: !1, line: 1, type: !5, isLocal: false, isDefinition: true)
!5 = !DIBasicType(name: "int", size: 32, encoding: DW_ATE_signed)
!6 = !DIGlobalVariableExpression(var: !7, expr: !DIExpression())
!7 = distinct !DIGlobalVariable(name: "wrong_size", scope: !0, file: !1, line: 2, type: !8, isLocal: false, isDefinition: true)
!8 = !DIBasicType(name: "long", size: 64, encoding: DW_ATE_signed)
!9 = !{i32 7, !"Dwarf Version", i32 5}
!10 = !{i32 2, !"Debug Info Version", i32 3}
