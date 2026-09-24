source_filename = "memory-fixed-accessors-contract.c"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpfel"

%config = type { i32, i32, i32, i32, i32, i32, i32, i32, i32, i32, i32, i32, i64 }
%map = type { ptr }

@bpf_capsule_config = constant %config { i32 0, i32 4096, i32 0, i32 0, i32 1, i32 4096, i32 1, i32 0, i32 0, i32 0, i32 1112556353, i32 8, i64 0 }, section ".rodata.bpfconfig", align 4
@bpf_heap_array = global %map zeroinitializer, section ".maps", align 8, !dbg !0
@bpf_call_stack = internal global [4096 x i8] zeroinitializer, align 8, !bpf.fiber.stack.size !13
@llvm.native_field_offset = external global i64
@native_capsule_address = global i64 0, section ".data.native", align 8
@native_kernel_pointer = external global ptr, section ".ksyms"

define i32 @read_any(ptr %address) {
entry:
  %value = load i32, ptr %address, align 4
  ret i32 %value
}

define void @write_any(ptr %address, i64 %value) {
entry:
  store i64 %value, ptr %address, align 8
  ret void
}

define i64 @read_align1(ptr %address) {
entry:
  %value = load i64, ptr %address, align 1
  ret i64 %value
}

define i64 @read_align2(ptr %address) {
entry:
  %value = load i64, ptr %address, align 2
  ret i64 %value
}

define void @write_align4(ptr %address, i64 %value) {
entry:
  store i64 %value, ptr %address, align 4
  ret void
}

declare extern_weak i64 @optional_kfunc() section ".ksyms"

declare void @register_callback(ptr) section ".ksyms"

define void @native_callback() !bpf.native !16 {
entry:
  ret void
}

define i1 @native_symbols() !bpf.native !16 {
entry:
  call void @register_callback(ptr @native_callback)
  %available = icmp ne ptr @optional_kfunc, null
  ret i1 %available
}

define i32 @native_kernel_fields(ptr %context) !bpf.native !16 {
entry:
  %bits = load i64, ptr %context, align 8
  %task = inttoptr i64 %bits to ptr
  %offset = load i64, ptr @llvm.native_field_offset, align 8
  %field = getelementptr i8, ptr %task, i64 %offset
  %member = load ptr, ptr %field, align 8
  %value = load i32, ptr %member, align 4
  %kernel = load ptr, ptr @native_kernel_pointer, align 8
  %other = load i32, ptr %kernel, align 4
  %sum = add i32 %value, %other
  ret i32 %sum
}

define i32 @native_capsule_access(i1 %choose) !bpf.native !16 {
entry:
  %bits = load i64, ptr @native_capsule_address, align 8
  %pointer = inttoptr i64 %bits to ptr
  %next = getelementptr i8, ptr %pointer, i64 4
  %selected = select i1 %choose, ptr %pointer, ptr %next
  %value = load i32, ptr %selected, align 4
  %image = load i32, ptr @bpf_call_stack, align 4
  %sum = add i32 %value, %image
  ret i32 %sum
}

!llvm.dbg.cu = !{!2}
!llvm.module.flags = !{!14, !15}

!0 = !DIGlobalVariableExpression(var: !1, expr: !DIExpression())
!1 = distinct !DIGlobalVariable(name: "bpf_heap_array", scope: !2, file: !3, line: 1, type: !5, isLocal: false, isDefinition: true)
!2 = distinct !DICompileUnit(language: DW_LANG_C11, file: !3, producer: "pass contract", isOptimized: false, runtimeVersion: 0, emissionKind: FullDebug, globals: !4)
!3 = !DIFile(filename: "memory-fixed-accessors-contract.c", directory: ".")
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
