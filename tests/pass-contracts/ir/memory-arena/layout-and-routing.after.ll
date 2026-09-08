source_filename = "memory-arena-contract.c"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpfel"

%config = type { i32, i32, i32, i32, i32, i32, i32, i32, i32, i32, i32, i32, i64 }
%arena_control = type { i32, i32, i64 }
%map = type { ptr }
%packed_pointer = type <{ i8, ptr }>

@bpf_capsule_config = constant %config { i32 4128, i32 4096, i32 12288, i32 16384, i32 1, i32 4096, i32 1, i32 1, i32 1, i32 0, i32 1112556353, i32 8, i64 0 }, section ".rodata.bpfconfig", align 4
@bpf_capsule_arena_control = global %arena_control zeroinitializer, section ".data.bpfctrl", align 8
@arena = global %map zeroinitializer, section ".maps", align 8, !dbg !0
@exchange = global [32 x i8] zeroinitializer, section ".data.exchange", align 8
@callback = internal addrspace(1) global ptr null, align 8
@initialized = internal addrspace(1) global i32 9, align 4
@packed = internal addrspace(1) global %packed_pointer <{ i8 7, ptr null }>, align 1
@__bpf_capsule_init_fixups.0.table = internal constant [1 x { i64, i64 }] [{ i64, i64 } { i64 sub (i64 ptrtoint (ptr addrspace(1) @callback to i64), i64 ptrtoint (ptr addrspace(1) @callback to i64)), i64 4311744512 }], section ".rodata.bpfinit", align 8, !dbg !5
@__bpf_capsule_init_fixups.1.table = internal constant [1 x { i64, i64 }] [{ i64, i64 } { i64 add (i64 sub (i64 ptrtoint (ptr addrspace(1) @packed to i64), i64 ptrtoint (ptr addrspace(1) @callback to i64)), i64 1), i64 4096 }], section ".rodata.bpfinit", align 8, !dbg !11

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

define i64 @sparse_addresses_in_module_order() {
entry:
  %bpf.arena.base = load i64, ptr getelementptr inbounds nuw (%arena_control, ptr @bpf_capsule_arena_control, i32 0, i32 2), align 8
  %bpf.arena.address = add i64 %bpf.arena.base, 4096
  %bpf.arena.program.pointer = inttoptr i64 %bpf.arena.address to ptr
  %bpf.arena.program.pointer.arena.word = ptrtoint ptr %bpf.arena.program.pointer to i64
  %bpf.arena.program.pointer.arena.span = inttoptr i64 %bpf.arena.program.pointer.arena.word to ptr addrspace(1)
  %bpf.arena.program.pointer.arena = addrspacecast ptr addrspace(1) %bpf.arena.program.pointer.arena.span to ptr
  %bpf.arena.address1 = add i64 %bpf.arena.base, 4112
  %bpf.arena.program.pointer2 = inttoptr i64 %bpf.arena.address1 to ptr
  %bpf.arena.program.pointer2.arena.word = ptrtoint ptr %bpf.arena.program.pointer2 to i64
  %bpf.arena.program.pointer2.arena.span = inttoptr i64 %bpf.arena.program.pointer2.arena.word to ptr addrspace(1)
  %bpf.arena.program.pointer2.arena = addrspacecast ptr addrspace(1) %bpf.arena.program.pointer2.arena.span to ptr
  %bpf.arena.address3 = add i64 %bpf.arena.base, 4120
  %bpf.arena.program.pointer4 = inttoptr i64 %bpf.arena.address3 to ptr
  %bpf.arena.program.pointer4.arena.word = ptrtoint ptr %bpf.arena.program.pointer4 to i64
  %bpf.arena.program.pointer4.arena.span = inttoptr i64 %bpf.arena.program.pointer4.arena.word to ptr addrspace(1)
  %bpf.arena.program.pointer4.arena = addrspacecast ptr addrspace(1) %bpf.arena.program.pointer4.arena.span to ptr
  %last = load volatile i64, ptr %bpf.arena.program.pointer4.arena, align 8
  %middle = load volatile i64, ptr %bpf.arena.program.pointer.arena, align 8
  %first = load volatile i64, ptr %bpf.arena.program.pointer2.arena, align 8
  %a = add i64 %last, %middle
  %b = add i64 %a, %first
  ret i64 %b
}

define i32 @late_copies(ptr %destination, ptr %source, i32 %count) {
entry:
  br label %loop

loop:                                             ; preds = %loop, %entry
  %remaining = phi i32 [ %count, %entry ], [ %next, %loop ]
  %source.word = ptrtoint ptr %source to i64
  %source.span = inttoptr i64 %source.word to ptr addrspace(1)
  %source.arena = addrspacecast ptr addrspace(1) %source.span to ptr
  %first = load volatile i8, ptr %source.arena, align 1
  %destination.word = ptrtoint ptr %destination to i64
  %destination.span = inttoptr i64 %destination.word to ptr addrspace(1)
  %destination.arena = addrspacecast ptr addrspace(1) %destination.span to ptr
  call void @llvm.memcpy.p0.p0.i64(ptr align 8 %destination.arena, ptr align 8 %source.arena, i64 16, i1 false)
  %second = load volatile i8, ptr %source.arena, align 1
  call void @llvm.memset.p0.i64(ptr align 8 %destination.arena, i8 0, i64 8, i1 false)
  call void @llvm.memmove.p0.p0.i64(ptr align 8 %source.arena, ptr align 8 %destination.arena, i64 8, i1 false)
  %next = sub i32 %remaining, 1
  %more = icmp sgt i32 %next, 0
  br i1 %more, label %loop, label %done

done:                                             ; preds = %loop
  %a = zext i8 %first to i32
  %b = zext i8 %second to i32
  %sum = add i32 %a, %b
  ret i32 %sum
}

define void @native_copy_operands(ptr %frame) {
entry:
  %local = alloca [32 x i8], align 8
  %frame.word = ptrtoint ptr %frame to i64
  %frame.span = inttoptr i64 %frame.word to ptr addrspace(1)
  %frame.arena = addrspacecast ptr addrspace(1) %frame.span to ptr
  call void @llvm.memcpy.p0.p0.i64(ptr align 8 %local, ptr align 8 %frame.arena, i64 32, i1 false)
  call void @llvm.memcpy.p0.p0.i64(ptr align 8 %frame.arena, ptr align 8 @exchange, i64 32, i1 false)
  call void @llvm.memset.p0.i64(ptr align 8 @exchange, i8 1, i64 32, i1 false)
  ret void
}

; Function Attrs: nocallback nofree nosync nounwind willreturn memory(argmem: readwrite)
declare void @llvm.memcpy.p0.p0.i64(ptr noalias writeonly captures(none), ptr noalias readonly captures(none), i64, i1 immarg) #0

; Function Attrs: nocallback nofree nosync nounwind willreturn memory(argmem: readwrite)
declare void @llvm.memmove.p0.p0.i64(ptr writeonly captures(none), ptr readonly captures(none), i64, i1 immarg) #0

; Function Attrs: nocallback nofree nosync nounwind willreturn memory(argmem: write)
declare void @llvm.memset.p0.i64(ptr writeonly captures(none), i8, i64, i1 immarg) #1

; Function Attrs: noinline
define internal i32 @__bpf_capsule_init() #2 !dbg !23 {
entry:
  %fixup.context = alloca { i64, i64 }, align 8, !dbg !27
  %bpf.view.base = load volatile i64, ptr getelementptr inbounds nuw (%config, ptr @bpf_capsule_config, i32 0, i32 12), align 8, !dbg !27
  %0 = atomicrmw add ptr @bpf_capsule_arena_control, i32 0 seq_cst, align 4, !dbg !27
  %1 = icmp eq i32 %0, 2, !dbg !27
  br i1 %1, label %done, label %claim, !dbg !27

claim:                                            ; preds = %entry
  %2 = cmpxchg ptr @bpf_capsule_arena_control, i32 0, i32 1 seq_cst seq_cst, align 4, !dbg !27
  %bpf.arena.init.won = extractvalue { i32, i1 } %2, 1, !dbg !27
  %bpf.arena.init.previous = extractvalue { i32, i1 } %2, 0, !dbg !27
  %3 = icmp eq i32 %bpf.arena.init.previous, 2, !dbg !27
  br i1 %bpf.arena.init.won, label %allocate, label %contested, !dbg !27

allocate:                                         ; preds = %claim
  %bpf.memory.end32 = load volatile i32, ptr getelementptr inbounds nuw (%config, ptr @bpf_capsule_config, i32 0, i32 3), align 4, !dbg !27
  %bpf.memory.end = zext i32 %bpf.memory.end32 to i64, !dbg !27
  %4 = add i64 %bpf.memory.end, 4095, !dbg !27
  %bpf.arena.selected.pages = lshr i64 %4, 12, !dbg !27
  %5 = trunc i64 %bpf.arena.selected.pages to i32, !dbg !27
  %6 = call ptr addrspace(1) @bpf_arena_alloc_pages(ptr @arena, ptr addrspace(1) null, i32 %5, i32 -1, i64 0), !dbg !27
  %7 = icmp ne ptr addrspace(1) %6, null, !dbg !27
  br i1 %7, label %initialize, label %failed, !dbg !27

initialize:                                       ; preds = %allocate
  %bpf.arena.base.word = ptrtoint ptr addrspace(1) %6 to i64, !dbg !27
  store i64 %bpf.arena.base.word, ptr getelementptr inbounds nuw (%arena_control, ptr @bpf_capsule_arena_control, i32 0, i32 2), align 8, !dbg !27
  %8 = getelementptr inbounds nuw { i64, i64 }, ptr %fixup.context, i32 0, i32 0, !dbg !27
  store i64 ptrtoint (ptr addrspace(1) @callback to i64), ptr %8, align 8, !dbg !27
  %9 = mul i64 %bpf.view.base, 1, !dbg !27
  %10 = add i64 0, %9, !dbg !27
  %11 = getelementptr inbounds nuw { i64, i64 }, ptr %fixup.context, i32 0, i32 1, !dbg !27
  store i64 %10, ptr %11, align 8, !dbg !27
  %12 = call i64 inttoptr (i64 181 to ptr)(i32 1, ptr @__bpf_capsule_init_fixups.0, ptr %fixup.context, i64 0), !dbg !27
  %13 = mul i64 %bpf.arena.base.word, 1, !dbg !27
  %14 = add i64 0, %13, !dbg !27
  %15 = getelementptr inbounds nuw { i64, i64 }, ptr %fixup.context, i32 0, i32 1, !dbg !27
  store i64 %14, ptr %15, align 8, !dbg !27
  %16 = call i64 inttoptr (i64 181 to ptr)(i32 1, ptr @__bpf_capsule_init_fixups.1, ptr %fixup.context, i64 0), !dbg !27
  %17 = atomicrmw xchg ptr @bpf_capsule_arena_control, i32 2 seq_cst, align 4, !dbg !27
  br label %done, !dbg !27

busy:                                             ; preds = %contested
  ret i32 -11, !dbg !27

failed:                                           ; preds = %allocate
  %18 = atomicrmw xchg ptr @bpf_capsule_arena_control, i32 0 seq_cst, align 4, !dbg !27
  ret i32 -12, !dbg !27

done:                                             ; preds = %contested, %initialize, %entry
  ret i32 0, !dbg !27

contested:                                        ; preds = %claim
  br i1 %3, label %done, label %busy, !dbg !27
}

declare !dbg !28 ptr addrspace(1) @bpf_arena_alloc_pages(ptr, ptr addrspace(1), i32, i32, i64) section ".ksyms"

; Function Attrs: noinline
define internal i64 @__bpf_capsule_init_fixups.0(i32 %index, ptr "bpf.capsule.stack.backing" %context) #2 !dbg !41 {
entry:
  %0 = icmp ult i32 %index, 1, !dbg !47
  br i1 %0, label %apply, label %done, !dbg !47

apply:                                            ; preds = %entry
  %1 = zext i32 %index to i64, !dbg !47
  %2 = getelementptr [1 x { i64, i64 }], ptr @__bpf_capsule_init_fixups.0.table, i64 0, i64 %1, !dbg !47
  %3 = getelementptr inbounds nuw { i64, i64 }, ptr %2, i32 0, i32 0, !dbg !47
  %4 = mul i64 %1, 16, !dbg !47
  %5 = add i64 0, %4, !dbg !47
  %bpf.global.offset.visible = call i64 asm sideeffect "", "=r,0"(i64 %5), !dbg !47
  %6 = icmp ule i64 %bpf.global.offset.visible, 8, !dbg !47
  %bpf.global.offset.bounded = select i1 %6, i64 %bpf.global.offset.visible, i64 0, !dbg !47
  %7 = getelementptr i8, ptr @__bpf_capsule_init_fixups.0.table, i64 %bpf.global.offset.bounded, !dbg !47
  %8 = load i64, ptr %7, align 8, !dbg !47
  %9 = getelementptr inbounds nuw { i64, i64 }, ptr %2, i32 0, i32 1, !dbg !47
  %10 = mul i64 %1, 16, !dbg !47
  %11 = add i64 8, %10, !dbg !47
  %bpf.global.offset.visible1 = call i64 asm sideeffect "", "=r,0"(i64 %11), !dbg !47
  %12 = icmp ule i64 %bpf.global.offset.visible1, 8, !dbg !47
  %bpf.global.offset.bounded2 = select i1 %12, i64 %bpf.global.offset.visible1, i64 0, !dbg !47
  %13 = getelementptr i8, ptr @__bpf_capsule_init_fixups.0.table, i64 %bpf.global.offset.bounded2, !dbg !47
  %14 = load i64, ptr %13, align 8, !dbg !47
  %15 = getelementptr inbounds nuw { i64, i64 }, ptr %context, i32 0, i32 0, !dbg !47
  %16 = load i64, ptr %15, align 8, !dbg !47
  %17 = getelementptr inbounds nuw { i64, i64 }, ptr %context, i32 0, i32 1, !dbg !47
  %18 = load i64, ptr %17, align 8, !dbg !47
  %19 = add i64 %16, %8, !dbg !47
  %20 = inttoptr i64 %19 to ptr, !dbg !47
  %.arena.word = ptrtoint ptr %20 to i64, !dbg !47
  %.arena.span = inttoptr i64 %.arena.word to ptr addrspace(1), !dbg !47
  %.arena = addrspacecast ptr addrspace(1) %.arena.span to ptr, !dbg !47
  %21 = add i64 %18, %14, !dbg !47
  store i64 %21, ptr %.arena, align 8, !dbg !47
  br label %done, !dbg !47

done:                                             ; preds = %apply, %entry
  ret i64 0, !dbg !47
}

; Function Attrs: noinline
define internal i64 @__bpf_capsule_init_fixups.1(i32 %index, ptr "bpf.capsule.stack.backing" %context) #2 !dbg !48 {
entry:
  %0 = icmp ult i32 %index, 1, !dbg !52
  br i1 %0, label %apply, label %done, !dbg !52

apply:                                            ; preds = %entry
  %1 = zext i32 %index to i64, !dbg !52
  %2 = getelementptr [1 x { i64, i64 }], ptr @__bpf_capsule_init_fixups.1.table, i64 0, i64 %1, !dbg !52
  %3 = getelementptr inbounds nuw { i64, i64 }, ptr %2, i32 0, i32 0, !dbg !52
  %4 = mul i64 %1, 16, !dbg !52
  %5 = add i64 0, %4, !dbg !52
  %bpf.global.offset.visible = call i64 asm sideeffect "", "=r,0"(i64 %5), !dbg !52
  %6 = icmp ule i64 %bpf.global.offset.visible, 8, !dbg !52
  %bpf.global.offset.bounded = select i1 %6, i64 %bpf.global.offset.visible, i64 0, !dbg !52
  %7 = getelementptr i8, ptr @__bpf_capsule_init_fixups.1.table, i64 %bpf.global.offset.bounded, !dbg !52
  %8 = load i64, ptr %7, align 8, !dbg !52
  %9 = getelementptr inbounds nuw { i64, i64 }, ptr %2, i32 0, i32 1, !dbg !52
  %10 = mul i64 %1, 16, !dbg !52
  %11 = add i64 8, %10, !dbg !52
  %bpf.global.offset.visible1 = call i64 asm sideeffect "", "=r,0"(i64 %11), !dbg !52
  %12 = icmp ule i64 %bpf.global.offset.visible1, 8, !dbg !52
  %bpf.global.offset.bounded2 = select i1 %12, i64 %bpf.global.offset.visible1, i64 0, !dbg !52
  %13 = getelementptr i8, ptr @__bpf_capsule_init_fixups.1.table, i64 %bpf.global.offset.bounded2, !dbg !52
  %14 = load i64, ptr %13, align 8, !dbg !52
  %15 = getelementptr inbounds nuw { i64, i64 }, ptr %context, i32 0, i32 0, !dbg !52
  %16 = load i64, ptr %15, align 8, !dbg !52
  %17 = getelementptr inbounds nuw { i64, i64 }, ptr %context, i32 0, i32 1, !dbg !52
  %18 = load i64, ptr %17, align 8, !dbg !52
  %19 = add i64 %16, %8, !dbg !52
  %20 = inttoptr i64 %19 to ptr, !dbg !52
  %.arena.word = ptrtoint ptr %20 to i64, !dbg !52
  %.arena.span = inttoptr i64 %.arena.word to ptr addrspace(1), !dbg !52
  %.arena = addrspacecast ptr addrspace(1) %.arena.span to ptr, !dbg !52
  %21 = add i64 %18, %14, !dbg !52
  store i64 %21, ptr %.arena, align 1, !dbg !52
  br label %done, !dbg !52

done:                                             ; preds = %apply, %entry
  ret i64 0, !dbg !52
}

; Function Attrs: noinline
define i32 @bpf_capsule_init() #2 section "syscall" !dbg !53 {
entry:
  %0 = call i32 @__bpf_capsule_init(), !dbg !54
  ret i32 %0, !dbg !54
}

attributes #0 = { nocallback nofree nosync nounwind willreturn memory(argmem: readwrite) }
attributes #1 = { nocallback nofree nosync nounwind willreturn memory(argmem: write) }
attributes #2 = { noinline }

!llvm.dbg.cu = !{!2}
!llvm.module.flags = !{!21, !22}

!0 = !DIGlobalVariableExpression(var: !1, expr: !DIExpression())
!1 = distinct !DIGlobalVariable(name: "arena", scope: !2, file: !3, line: 1, type: !13, isLocal: false, isDefinition: true)
!2 = distinct !DICompileUnit(language: DW_LANG_C11, file: !3, producer: "pass contract", isOptimized: false, runtimeVersion: 0, emissionKind: FullDebug, globals: !4)
!3 = !DIFile(filename: "memory-arena-contract.c", directory: ".")
!4 = !{!0, !5, !11}
!5 = !DIGlobalVariableExpression(var: !6, expr: !DIExpression())
!6 = distinct !DIGlobalVariable(name: "__bpf_capsule_init_fixups.0.table", linkageName: "__bpf_capsule_init_fixups.0.table", scope: !2, file: !3, type: !7, isLocal: true, isDefinition: true)
!7 = !DICompositeType(tag: DW_TAG_array_type, baseType: !8, size: 128, align: 8, elements: !9)
!8 = !DIBasicType(name: "char", size: 8, encoding: DW_ATE_signed_char)
!9 = !{!10}
!10 = !DISubrange(count: 16, lowerBound: 0)
!11 = !DIGlobalVariableExpression(var: !12, expr: !DIExpression())
!12 = distinct !DIGlobalVariable(name: "__bpf_capsule_init_fixups.1.table", linkageName: "__bpf_capsule_init_fixups.1.table", scope: !2, file: !3, type: !7, isLocal: true, isDefinition: true)
!13 = distinct !DICompositeType(tag: DW_TAG_structure_type, name: "arena_map", file: !3, line: 1, size: 64, elements: !14)
!14 = !{!15}
!15 = !DIDerivedType(tag: DW_TAG_member, name: "max_entries", scope: !13, file: !3, line: 1, baseType: !16, size: 64)
!16 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !17, size: 64)
!17 = !DICompositeType(tag: DW_TAG_array_type, baseType: !18, size: 160, elements: !19)
!18 = !DIBasicType(name: "int", size: 32, encoding: DW_ATE_signed)
!19 = !{!20}
!20 = !DISubrange(count: 5, lowerBound: 0)
!21 = !{i32 2, !"Dwarf Version", i32 4}
!22 = !{i32 2, !"Debug Info Version", i32 3}
!23 = distinct !DISubprogram(name: "__bpf_capsule_init.impl", linkageName: "__bpf_capsule_init.impl", scope: null, file: !3, type: !24, spFlags: DISPFlagLocalToUnit | DISPFlagDefinition, unit: !2, retainedNodes: !26)
!24 = !DISubroutineType(types: !25)
!25 = !{!18}
!26 = !{}
!27 = !DILocation(line: 0, scope: !23)
!28 = !DISubprogram(name: "bpf_arena_alloc_pages", linkageName: "bpf_arena_alloc_pages", scope: null, file: !3, type: !29, spFlags: 0, retainedNodes: !35)
!29 = !DISubroutineType(types: !30)
!30 = !{!31, !31, !31, !33, !18, !34}
!31 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !32, size: 64)
!32 = !DIBasicType(tag: DW_TAG_unspecified_type, name: "void")
!33 = !DIBasicType(name: "unsigned int", size: 32, encoding: DW_ATE_unsigned)
!34 = !DIBasicType(name: "unsigned long long", size: 64, encoding: DW_ATE_unsigned)
!35 = !{!36, !37, !38, !39, !40}
!36 = !DILocalVariable(arg: 1, scope: !28, file: !3, type: !31)
!37 = !DILocalVariable(arg: 2, scope: !28, file: !3, type: !31)
!38 = !DILocalVariable(arg: 3, scope: !28, file: !3, type: !33)
!39 = !DILocalVariable(arg: 4, scope: !28, file: !3, type: !18)
!40 = !DILocalVariable(arg: 5, scope: !28, file: !3, type: !34)
!41 = distinct !DISubprogram(name: "__bpf_capsule_init_fixups.0", linkageName: "__bpf_capsule_init_fixups.0", scope: null, file: !3, type: !42, spFlags: DISPFlagLocalToUnit | DISPFlagDefinition, unit: !2, retainedNodes: !44)
!42 = !DISubroutineType(types: !43)
!43 = !{!34, !33, !31}
!44 = !{!45, !46}
!45 = !DILocalVariable(name: "index", arg: 1, scope: !41, file: !3, type: !33)
!46 = !DILocalVariable(name: "context", arg: 2, scope: !41, file: !3, type: !31)
!47 = !DILocation(line: 0, scope: !41)
!48 = distinct !DISubprogram(name: "__bpf_capsule_init_fixups.1", linkageName: "__bpf_capsule_init_fixups.1", scope: null, file: !3, type: !42, spFlags: DISPFlagLocalToUnit | DISPFlagDefinition, unit: !2, retainedNodes: !49)
!49 = !{!50, !51}
!50 = !DILocalVariable(name: "index", arg: 1, scope: !48, file: !3, type: !33)
!51 = !DILocalVariable(name: "context", arg: 2, scope: !48, file: !3, type: !31)
!52 = !DILocation(line: 0, scope: !48)
!53 = distinct !DISubprogram(name: "bpf_capsule_init", linkageName: "bpf_capsule_init", scope: null, file: !3, type: !24, spFlags: DISPFlagDefinition, unit: !2, retainedNodes: !26)
!54 = !DILocation(line: 0, scope: !53)
