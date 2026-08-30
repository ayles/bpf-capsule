source_filename = "memory-fixed-stack-contract.c"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpfel"

%config = type { i32, i32, i32, i32, i32, i32, i32, i32, i32, i32, i32, i32, i64 }
%map = type { ptr }

@bpf_capsule_config = constant %config { i32 0, i32 4096, i32 0, i32 0, i32 1, i32 4096, i32 1, i32 0, i32 0, i32 0, i32 1112556353, i32 5, i64 0 }, section ".rodata.bpfconfig", align 4
@bpf_heap_array = global %map zeroinitializer, section ".maps", align 8, !dbg !0
@bpf_call_stack = internal global [4096 x i8] zeroinitializer, align 8, !bpf.fiber.stack.size !13

declare ptr @__bpf_capsule_stack_region(i32)

define ptr @resolve_stack(i32 %fiber) {
entry:
  %base = call ptr @__bpf_capsule_stack_region(i32 %fiber)
  ret ptr %base
}

define i32 @read_frame(i32 %sp, ptr "bpf.capsule.stack.backing" %stack_base) {
entry:
  %wide = zext i32 %sp to i64
  %offset = and i64 %wide, 4095
  %frame = getelementptr i8, ptr @bpf_call_stack, i64 %offset
  call void asm sideeffect "# bpf_capsule_stack_anchor", "r"(ptr %stack_base)
  %field = getelementptr i8, ptr %frame, i64 8
  %value = load i32, ptr %field, align 4
  ret i32 %value
}

define i32 @read_flattened_frame(i32 %sp, ptr "bpf.capsule.control" %fiber_control, ptr "bpf.capsule.stack.backing" %stack_base) !bpf.capsule.flatten.unit !16 {
entry:
  %wide = zext i32 %sp to i64
  %offset = and i64 %wide, 4095
  %frame = getelementptr i8, ptr @bpf_call_stack, i64 %offset
  call void asm sideeffect "# bpf_capsule_stack_anchor", "r"(ptr %stack_base)
  %field = getelementptr i8, ptr %frame, i64 8
  %value = load i32, ptr %field, align 4
  ret i32 %value
}

!llvm.dbg.cu = !{!2}
!llvm.module.flags = !{!14, !15}

!0 = !DIGlobalVariableExpression(var: !1, expr: !DIExpression())
!1 = distinct !DIGlobalVariable(name: "bpf_heap_array", scope: !2, file: !3, line: 1, type: !5, isLocal: false, isDefinition: true)
!2 = distinct !DICompileUnit(language: DW_LANG_C11, file: !3, producer: "pass contract", isOptimized: false, runtimeVersion: 0, emissionKind: FullDebug, globals: !4)
!3 = !DIFile(filename: "memory-fixed-stack-contract.c", directory: ".")
!4 = !{!0}
!5 = distinct !DICompositeType(tag: DW_TAG_structure_type, name: "heap_array_map", file: !3, line: 1, size: 64, elements: !6)
!6 = !{!7}
!7 = !DIDerivedType(tag: DW_TAG_member, name: "max_entries", scope: !5, file: !3, line: 1, baseType: !8, size: 64)
!8 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !9, size: 64)
!9 = !DICompositeType(tag: DW_TAG_array_type, baseType: !10, size: 32, elements: !11)
!10 = !DIBasicType(name: "int", size: 32, encoding: DW_ATE_signed)
!11 = !{!12}
!12 = !DISubrange(count: 1)
!13 = !{i64 4096}
!14 = !{i32 2, !"Dwarf Version", i32 4}
!15 = !{i32 2, !"Debug Info Version", i32 3}
!16 = !{}
