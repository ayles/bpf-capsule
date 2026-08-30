source_filename = "memory-arena-contract.c"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpfel"

%config = type { i32, i32, i32, i32, i32, i32, i32, i32, i32, i32, i32, i32, i64 }
%arena_control = type { i32, i32, i64 }
%map = type { ptr }
%packed_pointer = type <{ i8, ptr }>

@bpf_capsule_config = constant %config { i32 0, i32 4096, i32 0, i32 0, i32 1, i32 4096, i32 1, i32 0, i32 1, i32 0, i32 1112556353, i32 5, i64 0 }, section ".rodata.bpfconfig", align 4
@bpf_capsule_arena_control = global %arena_control zeroinitializer, section ".data.bpfctrl", align 8
@arena = global %map zeroinitializer, section ".maps", align 8, !dbg !0
@bpf_call_stack = internal global [4096 x i8] zeroinitializer, align 8, !bpf.fiber.stack.size !13
@initialized = internal global i32 9, align 4
@sparse = internal global [16 x i8] zeroinitializer, align 8
@packed = internal global %packed_pointer <{ i8 7, ptr @sparse }>, align 1

define i32 @read(i64 %index) {
entry:
  %slot = getelementptr [16 x i8], ptr @sparse, i64 0, i64 %index
  %byte = load i8, ptr %slot, align 1
  %wide = zext i8 %byte to i32
  %constant = load i32, ptr @initialized, align 4
  %result = add i32 %constant, %wide
  ret i32 %result
}

define i1 @is_sparse(ptr %candidate) {
entry:
  %same = icmp eq ptr %candidate, @sparse
  ret i1 %same
}

!llvm.dbg.cu = !{!2}
!llvm.module.flags = !{!14, !15}

!0 = !DIGlobalVariableExpression(var: !1, expr: !DIExpression())
!1 = distinct !DIGlobalVariable(name: "arena", scope: !2, file: !3, line: 1, type: !5, isLocal: false, isDefinition: true)
!2 = distinct !DICompileUnit(language: DW_LANG_C11, file: !3, producer: "pass contract", isOptimized: false, runtimeVersion: 0, emissionKind: FullDebug, globals: !4)
!3 = !DIFile(filename: "memory-arena-contract.c", directory: ".")
!4 = !{!0}
!5 = distinct !DICompositeType(tag: DW_TAG_structure_type, name: "arena_map", file: !3, line: 1, size: 64, elements: !6)
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
