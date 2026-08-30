source_filename = "softfloat-declaration-debug.ll"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpfel"

declare !dbg !4 float @external_float(float)

define float @roundtrip(float %value) !dbg !9 {
entry:
  %result = call float @external_float(float %value), !dbg !10
  ret float %result, !dbg !11
}

!llvm.dbg.cu = !{!0}
!llvm.module.flags = !{!2, !3}

!0 = distinct !DICompileUnit(language: DW_LANG_C11, file: !1, producer: "pass contract", isOptimized: true, runtimeVersion: 0, emissionKind: FullDebug, splitDebugInlining: false, nameTableKind: None)
!1 = !DIFile(filename: "softfloat-declaration-debug.c", directory: "/")
!2 = !{i32 7, !"Dwarf Version", i32 5}
!3 = !{i32 2, !"Debug Info Version", i32 3}
!4 = !DISubprogram(name: "external_float", scope: !1, file: !1, line: 1, type: !5, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized, retainedNodes: !8)
!5 = !DISubroutineType(types: !6)
!6 = !{!7, !7}
!7 = !DIBasicType(name: "float", size: 32, encoding: DW_ATE_float)
!8 = !{}
!9 = distinct !DISubprogram(name: "roundtrip", scope: !1, file: !1, line: 3, type: !5, scopeLine: 3, flags: DIFlagPrototyped | DIFlagAllCallsDescribed, spFlags: DISPFlagDefinition | DISPFlagOptimized, unit: !0, retainedNodes: !8)
!10 = !DILocation(line: 4, column: 12, scope: !9)
!11 = !DILocation(line: 4, column: 5, scope: !9)
