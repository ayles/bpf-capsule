source_filename = "stackify-native-runtime-btf.c"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpfel"

%fiber_control = type { i32, i32, i64, i64, i64, i32, i32 }
%config = type { i32, i32, i32, i32, i32, i32, i32, i32, i32, i32, i32, i32, i64 }

@bpf_capsule_fibers = global [1 x %fiber_control] zeroinitializer, section ".bss.bpfctrl", align 8
@bpf_capsule_config = constant %config { i32 0, i32 4096, i32 0, i32 0, i32 1, i32 4096, i32 1, i32 0, i32 1, i32 0, i32 1112556353, i32 5, i64 0 }, section ".rodata.bpfconfig", align 4

declare i32 @__bpf_capsule_trampoline_step(i32, ptr)

declare void @__bpf_capsule_yield()

define i32 @__bpf_capsule_trampoline_l1(i32 %fiber, ptr %control) #0 {
entry:
  %status = call i32 @__bpf_capsule_trampoline_step(i32 %fiber, ptr %control)
  ret i32 %status
}

define i32 @__bpf_capsule_trampoline(i32 %fiber) #0 {
entry:
  %control = getelementptr [1 x %fiber_control], ptr @bpf_capsule_fibers, i32 0, i32 %fiber
  %status = call i32 @__bpf_capsule_trampoline_l1(i32 %fiber, ptr %control)
  ret i32 %status
}

define i64 @__bpf_runtime_glue(i32 %value) !dbg !4 {
entry:
  %wide = zext i32 %value to i64, !dbg !10
  ret i64 %wide, !dbg !11
}

define i32 @root(i32 %value) !bpf.capsule !9 {
entry:
  call void @__bpf_capsule_yield()
  %result = add i32 %value, 1
  ret i32 %result
}

define i32 @start(i32 %fiber) section "syscall" !bpf.native !9 {
entry:
  %native = call i64 @__bpf_runtime_glue(i32 7)
  %result = call i32 @root(i32 41) [ "bpf.capsule.call"(i32 %fiber) ]
  ret i32 %result
}

attributes #0 = { "capsule.trampoline" }

!llvm.dbg.cu = !{!0}
!llvm.module.flags = !{!2, !3}

!0 = distinct !DICompileUnit(language: DW_LANG_C11, file: !1, producer: "pass contract", isOptimized: true, runtimeVersion: 0, emissionKind: FullDebug, splitDebugInlining: false, nameTableKind: None)
!1 = !DIFile(filename: "stackify-native-runtime-btf.c", directory: "/")
!2 = !{i32 7, !"Dwarf Version", i32 5}
!3 = !{i32 2, !"Debug Info Version", i32 3}
!4 = distinct !DISubprogram(name: "__bpf_runtime_glue", scope: !1, file: !1, line: 1, type: !5, scopeLine: 1, flags: DIFlagPrototyped, spFlags: DISPFlagDefinition | DISPFlagOptimized, unit: !0, retainedNodes: !9)
!5 = !DISubroutineType(types: !6)
!6 = !{!7, !8}
!7 = !DIBasicType(name: "unsigned long", size: 64, encoding: DW_ATE_unsigned)
!8 = !DIBasicType(name: "unsigned int", size: 32, encoding: DW_ATE_unsigned)
!9 = !{}
!10 = !DILocation(line: 2, column: 12, scope: !4)
!11 = !DILocation(line: 2, column: 5, scope: !4)
