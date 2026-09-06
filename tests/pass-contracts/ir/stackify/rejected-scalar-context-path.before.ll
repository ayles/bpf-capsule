source_filename = "stackify-rejected-scalar-context-path.ll"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpfel"

%fiber_control = type { i32, i32, i64, i64, i64, i32, i32 }
%config = type { i32, i32, i32, i32, i32, i32, i32, i32, i32, i32, i32, i32, i64 }

@bpf_capsule_fibers = global [1 x %fiber_control] zeroinitializer, section ".bss.bpfctrl", align 8
@bpf_capsule_config = constant %config zeroinitializer, section ".rodata.bpfconfig", align 4

declare ptr @__bpf_capsule_current_ctx()

define void @context_leaf() !bpf.capsule !4 {
entry:
  %context = call ptr @__bpf_capsule_current_ctx()
  call void asm sideeffect "", "r"(ptr %context)
  ret void
}

define void @borrowed_root() !bpf.capsule !4 {
entry:
  call void @context_leaf()
  ret void
}

define void @scalar_root() !bpf.capsule !4 {
entry:
  call void @context_leaf()
  ret void
}

define i32 @start_context(ptr %context, i32 %fiber) section "xdp" !dbg !5 !bpf.native !4 {
entry:
  call void @borrowed_root() [ "bpf.capsule.call"(i32 %fiber, ptr %context) ]
  ret i32 2
}

define i32 @start_scalar(i32 %fiber) section "syscall" !bpf.native !4 {
entry:
  call void @scalar_root() [ "bpf.capsule.call"(i32 %fiber) ]
  ret i32 0
}

!llvm.dbg.cu = !{!0}
!llvm.module.flags = !{!2, !3}

!0 = distinct !DICompileUnit(language: DW_LANG_C11, file: !1, producer: "pass contract", isOptimized: false, runtimeVersion: 0, emissionKind: FullDebug)
!1 = !DIFile(filename: "stackify-rejected-scalar-context-path.c", directory: "/")
!2 = !{i32 7, !"Dwarf Version", i32 5}
!3 = !{i32 2, !"Debug Info Version", i32 3}
!4 = !{}
!5 = distinct !DISubprogram(name: "start_context", scope: !1, file: !1, type: !6, spFlags: DISPFlagDefinition, unit: !0)
!6 = !DISubroutineType(types: !7)
!7 = !{!8, !9, !8}
!8 = !DIBasicType(name: "int", size: 32, encoding: DW_ATE_signed)
!9 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !10, size: 64)
!10 = distinct !DICompositeType(tag: DW_TAG_structure_type, name: "xdp_md", file: !1, size: 192)
