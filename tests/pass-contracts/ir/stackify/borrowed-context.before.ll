source_filename = "stackify-borrowed-context.ll"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpfel"

%fiber_control = type { i32, i32, i64, i64, i64, i32, i32 }
%config = type { i32, i32, i32, i32, i32, i32, i32, i32, i32, i32, i32, i32, i64 }

@bpf_capsule_fibers = global [1 x %fiber_control] zeroinitializer, section ".bss.bpfctrl", align 8
@bpf_capsule_config = constant %config { i32 0, i32 4096, i32 0, i32 0, i32 1, i32 4096, i32 1, i32 0, i32 1, i32 0, i32 1112556353, i32 5, i64 0 }, section ".rodata.bpfconfig", align 4

declare i32 @__bpf_capsule_trampoline_step(i32, ptr)

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

declare i32 @__bpf_capsule_trampoline_ctx_step(ptr, i32, ptr)

define i32 @__bpf_capsule_trampoline_ctx_l1(ptr %context, i32 %fiber, ptr %control) #0 {
entry:
  %status = call i32 @__bpf_capsule_trampoline_ctx_step(ptr %context, i32 %fiber, ptr %control)
  ret i32 %status
}

define i32 @__bpf_capsule_trampoline_ctx(ptr %context, i32 %fiber) #0 {
entry:
  %control = getelementptr [1 x %fiber_control], ptr @bpf_capsule_fibers, i32 0, i32 %fiber
  %status = call i32 @__bpf_capsule_trampoline_ctx_l1(ptr %context, i32 %fiber, ptr %control)
  ret i32 %status
}

define i32 @context_helper(ptr %context, i32 %value) !bpf.capsule !4 {
entry:
  call void asm sideeffect "", "r"(ptr %context)
  %result = add i32 %value, 1
  ret i32 %result
}

define i32 @borrowed_root(ptr "bpf.capsule.borrowed" %context) !dbg !5 !bpf.capsule !4 {
entry:
  %first = call i32 @context_helper(ptr %context, i32 5)
  %second = call i32 @context_helper(ptr %context, i32 %first)
  ret i32 %second
}

define i32 @start(ptr %context, i32 %fiber) section "xdp" !bpf.native !4 {
entry:
  %result = call i32 @borrowed_root(ptr %context) [ "bpf.capsule.call"(i32 %fiber) ]
  ret i32 %result
}

attributes #0 = { "capsule.trampoline" }

!llvm.dbg.cu = !{!0}
!llvm.module.flags = !{!2, !3}

!0 = distinct !DICompileUnit(language: DW_LANG_C11, file: !1, producer: "pass contract", isOptimized: false, runtimeVersion: 0, emissionKind: FullDebug)
!1 = !DIFile(filename: "stackify-borrowed-context.c", directory: "/")
!2 = !{i32 7, !"Dwarf Version", i32 5}
!3 = !{i32 2, !"Debug Info Version", i32 3}
!4 = !{}
!5 = distinct !DISubprogram(name: "borrowed_root", scope: !1, file: !1, type: !6, spFlags: DISPFlagDefinition, unit: !0)
!6 = !DISubroutineType(types: !7)
!7 = !{!8, !9}
!8 = !DIBasicType(name: "int", size: 32, encoding: DW_ATE_signed)
!9 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !10, size: 64)
!10 = distinct !DICompositeType(tag: DW_TAG_structure_type, name: "xdp_md", file: !1, size: 192)
