source_filename = "memory-arena-contract.c"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpfel"

%config = type { i32, i32, i32, i32, i32, i32, i32, i32, i32, i32, i32, i32, i64 }
%arena_control = type { i32, i32, i64 }
%map = type { ptr }
%packed_pointer = type <{ i8, ptr }>

@bpf_capsule_config = constant %config { i32 4112, i32 4096, i32 12288, i32 16384, i32 1, i32 4096, i32 1, i32 1, i32 1, i32 0, i32 1112556353, i32 5, i64 0 }, section ".rodata.bpfconfig", align 4
@bpf_capsule_arena_control = global %arena_control zeroinitializer, section ".data.bpfctrl", align 8
@arena = global %map zeroinitializer, section ".maps", align 8, !dbg !0
@initialized = internal addrspace(1) global i32 9, align 4
@packed = internal addrspace(1) global %packed_pointer <{ i8 7, ptr null }>, align 1

define i32 @read(i64 %index) {
entry:
  %.arena = addrspacecast ptr addrspace(1) inttoptr (i64 ptrtoint (ptr inttoptr (i64 ptrtoint (ptr addrspace(1) @initialized to i64) to ptr) to i64) to ptr addrspace(1)) to ptr
  %bpf.arena.base = load i64, ptr getelementptr inbounds nuw (%arena_control, ptr @bpf_capsule_arena_control, i32 0, i32 2), align 8
  %bpf.arena.address = add i64 %bpf.arena.base, 4096
  %bpf.arena.program.pointer = inttoptr i64 %bpf.arena.address to ptr
  %bpf.arena.program.pointer.arena.word = ptrtoint ptr %bpf.arena.program.pointer to i64
  %bpf.arena.program.pointer.arena.span = inttoptr i64 %bpf.arena.program.pointer.arena.word to ptr addrspace(1)
  %bpf.arena.program.pointer.arena = addrspacecast ptr addrspace(1) %bpf.arena.program.pointer.arena.span to ptr
  %slot = getelementptr [16 x i8], ptr %bpf.arena.program.pointer, i64 0, i64 %index
  %slot.arena = getelementptr [16 x i8], ptr %bpf.arena.program.pointer.arena, i64 0, i64 %index
  %byte = load i8, ptr %slot.arena, align 1
  %wide = zext i8 %byte to i32
  %constant = load i32, ptr %.arena, align 4
  %result = add i32 %constant, %wide
  ret i32 %result
}

define i1 @is_sparse(ptr %candidate) {
entry:
  %bpf.arena.base = load i64, ptr getelementptr inbounds nuw (%arena_control, ptr @bpf_capsule_arena_control, i32 0, i32 2), align 8
  %bpf.arena.address = add i64 %bpf.arena.base, 4096
  %bpf.arena.program.pointer = inttoptr i64 %bpf.arena.address to ptr
  %same = icmp eq ptr %candidate, %bpf.arena.program.pointer
  ret i1 %same
}

; Function Attrs: noinline
define internal i32 @__bpf_capsule_init() #0 !dbg !15 !bpf.capsule.init !18 {
entry:
  %0 = atomicrmw add ptr @bpf_capsule_arena_control, i32 0 seq_cst, align 4, !dbg !19
  %1 = icmp eq i32 %0, 2, !dbg !19
  br i1 %1, label %done, label %claim, !dbg !19

claim:                                            ; preds = %entry
  %2 = cmpxchg ptr @bpf_capsule_arena_control, i32 0, i32 1 seq_cst seq_cst, align 4, !dbg !19
  %bpf.arena.init.won = extractvalue { i32, i1 } %2, 1, !dbg !19
  %bpf.arena.init.previous = extractvalue { i32, i1 } %2, 0, !dbg !19
  %3 = icmp eq i32 %bpf.arena.init.previous, 2, !dbg !19
  br i1 %bpf.arena.init.won, label %allocate, label %contested, !dbg !19

allocate:                                         ; preds = %claim
  %bpf.memory.end32 = load volatile i32, ptr getelementptr inbounds nuw (%config, ptr @bpf_capsule_config, i32 0, i32 3), align 4, !dbg !19
  %bpf.memory.end = zext i32 %bpf.memory.end32 to i64, !dbg !19
  %4 = add i64 %bpf.memory.end, 4095, !dbg !19
  %bpf.arena.selected.pages = lshr i64 %4, 12, !dbg !19
  %5 = trunc i64 %bpf.arena.selected.pages to i32, !dbg !19
  %6 = call ptr addrspace(1) @bpf_arena_alloc_pages(ptr @arena, ptr addrspace(1) null, i32 %5, i32 -1, i64 0), !dbg !19
  %7 = icmp ne ptr addrspace(1) %6, null, !dbg !19
  br i1 %7, label %initialize, label %failed, !dbg !19

initialize:                                       ; preds = %allocate
  %bpf.arena.base.word = ptrtoint ptr addrspace(1) %6 to i64, !dbg !19
  store i64 %bpf.arena.base.word, ptr getelementptr inbounds nuw (%arena_control, ptr @bpf_capsule_arena_control, i32 0, i32 2), align 8, !dbg !19
  %bpf.arena.address = add i64 %bpf.arena.base.word, 4096, !dbg !19
  %bpf.arena.program.pointer = inttoptr i64 %bpf.arena.address to ptr, !dbg !19
  store ptr %bpf.arena.program.pointer, ptr addrspace(1) getelementptr (i8, ptr addrspace(1) @packed, i64 1), align 1, !dbg !19
  %8 = atomicrmw xchg ptr @bpf_capsule_arena_control, i32 2 seq_cst, align 4, !dbg !19
  br label %done, !dbg !19

busy:                                             ; preds = %contested
  ret i32 -11, !dbg !19

failed:                                           ; preds = %allocate
  %9 = atomicrmw xchg ptr @bpf_capsule_arena_control, i32 0 seq_cst, align 4, !dbg !19
  ret i32 -12, !dbg !19

done:                                             ; preds = %contested, %initialize, %entry
  ret i32 0, !dbg !19

contested:                                        ; preds = %claim
  br i1 %3, label %done, label %busy, !dbg !19
}

declare !dbg !20 ptr addrspace(1) @bpf_arena_alloc_pages(ptr, ptr addrspace(1), i32, i32, i64) section ".ksyms"

; Function Attrs: noinline
define i32 @bpf_capsule_init() #0 section "syscall" !dbg !33 {
entry:
  %0 = call i32 @__bpf_capsule_init(), !dbg !34
  ret i32 %0, !dbg !34
}

attributes #0 = { noinline }

!llvm.dbg.cu = !{!2}
!llvm.module.flags = !{!13, !14}

!0 = !DIGlobalVariableExpression(var: !1, expr: !DIExpression())
!1 = distinct !DIGlobalVariable(name: "arena", scope: !2, file: !3, line: 1, type: !5, isLocal: false, isDefinition: true)
!2 = distinct !DICompileUnit(language: DW_LANG_C11, file: !3, producer: "pass contract", isOptimized: false, runtimeVersion: 0, emissionKind: FullDebug, globals: !4)
!3 = !DIFile(filename: "memory-arena-contract.c", directory: ".")
!4 = !{!0}
!5 = distinct !DICompositeType(tag: DW_TAG_structure_type, name: "arena_map", file: !3, line: 1, size: 64, elements: !6)
!6 = !{!7}
!7 = !DIDerivedType(tag: DW_TAG_member, name: "max_entries", scope: !5, file: !3, line: 1, baseType: !8, size: 64)
!8 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !9, size: 64)
!9 = !DICompositeType(tag: DW_TAG_array_type, baseType: !10, size: 160, elements: !11)
!10 = !DIBasicType(name: "int", size: 32, encoding: DW_ATE_signed)
!11 = !{!12}
!12 = !DISubrange(count: 5, lowerBound: 0)
!13 = !{i32 2, !"Dwarf Version", i32 4}
!14 = !{i32 2, !"Debug Info Version", i32 3}
!15 = distinct !DISubprogram(name: "__bpf_capsule_init.impl", linkageName: "__bpf_capsule_init.impl", scope: null, file: !3, type: !16, spFlags: DISPFlagDefinition, unit: !2, retainedNodes: !18)
!16 = !DISubroutineType(types: !17)
!17 = !{!10}
!18 = !{}
!19 = !DILocation(line: 0, scope: !15)
!20 = !DISubprogram(name: "bpf_arena_alloc_pages", linkageName: "bpf_arena_alloc_pages", scope: null, file: !3, type: !21, spFlags: 0, retainedNodes: !27)
!21 = !DISubroutineType(types: !22)
!22 = !{!23, !23, !23, !25, !10, !26}
!23 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !24, size: 64)
!24 = !DIBasicType(tag: DW_TAG_unspecified_type, name: "void")
!25 = !DIBasicType(name: "unsigned int", size: 32, encoding: DW_ATE_unsigned)
!26 = !DIBasicType(name: "unsigned long long", size: 64, encoding: DW_ATE_unsigned)
!27 = !{!28, !29, !30, !31, !32}
!28 = !DILocalVariable(arg: 1, scope: !20, file: !3, type: !23)
!29 = !DILocalVariable(arg: 2, scope: !20, file: !3, type: !23)
!30 = !DILocalVariable(arg: 3, scope: !20, file: !3, type: !25)
!31 = !DILocalVariable(arg: 4, scope: !20, file: !3, type: !10)
!32 = !DILocalVariable(arg: 5, scope: !20, file: !3, type: !26)
!33 = distinct !DISubprogram(name: "bpf_capsule_init", linkageName: "bpf_capsule_init", scope: null, file: !3, type: !16, spFlags: DISPFlagDefinition, unit: !2, retainedNodes: !18)
!34 = !DILocation(line: 0, scope: !33)
