source_filename = "memory-fixed-accessors-contract.c"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpfel"

%config = type { i32, i32, i32, i32, i32, i32, i32, i32, i32, i32, i32, i32, i64, i64 }
%map = type { ptr }

@bpf_capsule_config = constant %config { i32 4096, i32 4096, i32 8388608, i32 8392704, i32 1, i32 4096, i32 1, i32 0, i32 0, i32 0, i32 1112556353, i32 6, i64 0, i64 2 }, section ".rodata.bpfconfig", align 4
@bpf_heap_array = global %map zeroinitializer, section ".maps", align 8, !dbg !0
@heap0 = global [4194304 x i8] zeroinitializer, section ".bss.heap0", align 8, !dbg !5
@heap1 = global [4194304 x i8] zeroinitializer, section ".bss.heap1", align 8, !dbg !11

define i32 @read_any(ptr %address) {
entry:
  %0 = ptrtoint ptr %address to i64
  %1 = call i64 @bpf_heap_load32(i64 %0)
  %2 = trunc i64 %1 to i32
  ret i32 %2
}

define void @write_any(ptr %address, i64 %value) {
entry:
  %0 = ptrtoint ptr %address to i64
  %1 = call i32 @bpf_heap_store64(i64 %0, i64 %value)
  ret void
}

define i64 @read_align1(ptr %address) {
entry:
  %0 = getelementptr i8, ptr %address, i64 0
  %1 = ptrtoint ptr %0 to i64
  %2 = call i64 @bpf_heap_load8(i64 %1)
  %3 = trunc i64 %2 to i8
  %4 = zext i8 %3 to i64
  %5 = shl i64 %4, 0
  %6 = or i64 0, %5
  %7 = getelementptr i8, ptr %address, i64 1
  %8 = ptrtoint ptr %7 to i64
  %9 = call i64 @bpf_heap_load8(i64 %8)
  %10 = trunc i64 %9 to i8
  %11 = zext i8 %10 to i64
  %12 = shl i64 %11, 8
  %13 = or i64 %6, %12
  %14 = getelementptr i8, ptr %address, i64 2
  %15 = ptrtoint ptr %14 to i64
  %16 = call i64 @bpf_heap_load8(i64 %15)
  %17 = trunc i64 %16 to i8
  %18 = zext i8 %17 to i64
  %19 = shl i64 %18, 16
  %20 = or i64 %13, %19
  %21 = getelementptr i8, ptr %address, i64 3
  %22 = ptrtoint ptr %21 to i64
  %23 = call i64 @bpf_heap_load8(i64 %22)
  %24 = trunc i64 %23 to i8
  %25 = zext i8 %24 to i64
  %26 = shl i64 %25, 24
  %27 = or i64 %20, %26
  %28 = getelementptr i8, ptr %address, i64 4
  %29 = ptrtoint ptr %28 to i64
  %30 = call i64 @bpf_heap_load8(i64 %29)
  %31 = trunc i64 %30 to i8
  %32 = zext i8 %31 to i64
  %33 = shl i64 %32, 32
  %34 = or i64 %27, %33
  %35 = getelementptr i8, ptr %address, i64 5
  %36 = ptrtoint ptr %35 to i64
  %37 = call i64 @bpf_heap_load8(i64 %36)
  %38 = trunc i64 %37 to i8
  %39 = zext i8 %38 to i64
  %40 = shl i64 %39, 40
  %41 = or i64 %34, %40
  %42 = getelementptr i8, ptr %address, i64 6
  %43 = ptrtoint ptr %42 to i64
  %44 = call i64 @bpf_heap_load8(i64 %43)
  %45 = trunc i64 %44 to i8
  %46 = zext i8 %45 to i64
  %47 = shl i64 %46, 48
  %48 = or i64 %41, %47
  %49 = getelementptr i8, ptr %address, i64 7
  %50 = ptrtoint ptr %49 to i64
  %51 = call i64 @bpf_heap_load8(i64 %50)
  %52 = trunc i64 %51 to i8
  %53 = zext i8 %52 to i64
  %54 = shl i64 %53, 56
  %55 = or i64 %48, %54
  ret i64 %55
}

define i64 @read_align2(ptr %address) {
entry:
  %0 = getelementptr i8, ptr %address, i64 0
  %1 = ptrtoint ptr %0 to i64
  %2 = call i64 @bpf_heap_load16(i64 %1)
  %3 = trunc i64 %2 to i16
  %4 = zext i16 %3 to i64
  %5 = shl i64 %4, 0
  %6 = or i64 0, %5
  %7 = getelementptr i8, ptr %address, i64 2
  %8 = ptrtoint ptr %7 to i64
  %9 = call i64 @bpf_heap_load16(i64 %8)
  %10 = trunc i64 %9 to i16
  %11 = zext i16 %10 to i64
  %12 = shl i64 %11, 16
  %13 = or i64 %6, %12
  %14 = getelementptr i8, ptr %address, i64 4
  %15 = ptrtoint ptr %14 to i64
  %16 = call i64 @bpf_heap_load16(i64 %15)
  %17 = trunc i64 %16 to i16
  %18 = zext i16 %17 to i64
  %19 = shl i64 %18, 32
  %20 = or i64 %13, %19
  %21 = getelementptr i8, ptr %address, i64 6
  %22 = ptrtoint ptr %21 to i64
  %23 = call i64 @bpf_heap_load16(i64 %22)
  %24 = trunc i64 %23 to i16
  %25 = zext i16 %24 to i64
  %26 = shl i64 %25, 48
  %27 = or i64 %20, %26
  ret i64 %27
}

define void @write_align4(ptr %address, i64 %value) {
entry:
  %0 = getelementptr i8, ptr %address, i64 0
  %1 = lshr i64 %value, 0
  %2 = trunc i64 %1 to i32
  %3 = ptrtoint ptr %0 to i64
  %4 = zext i32 %2 to i64
  %5 = call i32 @bpf_heap_store32(i64 %3, i64 %4)
  %6 = getelementptr i8, ptr %address, i64 4
  %7 = lshr i64 %value, 32
  %8 = trunc i64 %7 to i32
  %9 = ptrtoint ptr %6 to i64
  %10 = zext i32 %8 to i64
  %11 = call i32 @bpf_heap_store32(i64 %9, i64 %10)
  ret void
}

; Function Attrs: noinline
define i64 @bpf_heap_load8(i64 %offset) #0 !dbg !23 {
entry:
  %bpf.heap.array.key.i = alloca i32, align 4, !dbg !29, !bpf.native.alloca !34
  %0 = and i64 %offset, 4194303, !dbg !35
  %bpf.heap.offset.visible = call i64 asm sideeffect "", "=r,0"(i64 %0), !dbg !35
  %1 = trunc i64 %offset to i32, !dbg !35
  %2 = lshr i32 %1, 22, !dbg !35
  %3 = icmp eq i32 %2, 0, !dbg !35
  br i1 %3, label %region.0, label %region.route, !dbg !35

array:                                            ; preds = %region.route
  call void @llvm.lifetime.start.p0(ptr %bpf.heap.array.key.i), !dbg !29
  %4 = and i64 %offset, 4194303, !dbg !29
  %bpf.heap.offset.visible.i = call i64 asm sideeffect "", "=r,0"(i64 %4), !dbg !29
  %5 = trunc i64 %offset to i32, !dbg !29
  %6 = lshr i32 %5, 22, !dbg !29
  %7 = icmp uge i32 %6, 2, !dbg !29
  br i1 %7, label %lookup.i, label %invalid.i, !dbg !29

lookup.i:                                         ; preds = %array
  %8 = sub i32 %6, 2, !dbg !29
  store i32 %8, ptr %bpf.heap.array.key.i, align 4, !dbg !29
  %bpf.heap.array.value.i = call ptr inttoptr (i64 1 to ptr)(ptr @bpf_heap_array, ptr %bpf.heap.array.key.i), !dbg !29
  %9 = icmp ne ptr %bpf.heap.array.value.i, null, !dbg !29
  br i1 %9, label %access.i, label %invalid.i, !dbg !29

access.i:                                         ; preds = %lookup.i
  %10 = getelementptr i8, ptr %bpf.heap.array.value.i, i64 %bpf.heap.offset.visible.i, !dbg !29
  %11 = load i8, ptr %10, align 1, !dbg !29
  %12 = zext i8 %11 to i64, !dbg !29
  call void @llvm.lifetime.end.p0(ptr %bpf.heap.array.key.i), !dbg !29
  br label %bpf_heap_array_load8.exit, !dbg !29

invalid.i:                                        ; preds = %lookup.i, %array
  call void @llvm.lifetime.end.p0(ptr %bpf.heap.array.key.i), !dbg !29
  br label %bpf_heap_array_load8.exit, !dbg !29

bpf_heap_array_load8.exit:                        ; preds = %invalid.i, %access.i
  %13 = phi i64 [ %12, %access.i ], [ 0, %invalid.i ]
  ret i64 %13, !dbg !35

region.route:                                     ; preds = %entry
  switch i32 %2, label %array [
    i32 1, label %region.1
  ], !dbg !35

region.0:                                         ; preds = %entry
  %14 = getelementptr i8, ptr @heap0, i64 %bpf.heap.offset.visible, !dbg !35
  %15 = load i8, ptr %14, align 1, !dbg !35
  %16 = zext i8 %15 to i64, !dbg !35
  ret i64 %16, !dbg !35

region.1:                                         ; preds = %region.route
  %17 = getelementptr i8, ptr @heap1, i64 %bpf.heap.offset.visible, !dbg !35
  %18 = load i8, ptr %17, align 1, !dbg !35
  %19 = zext i8 %18 to i64, !dbg !35
  ret i64 %19, !dbg !35

invalid:                                          ; No predecessors!
  ret i64 0, !dbg !35
}

; Function Attrs: nocallback nofree nosync nounwind willreturn memory(argmem: readwrite)
declare void @llvm.lifetime.start.p0(ptr captures(none)) #1

; Function Attrs: nocallback nofree nosync nounwind willreturn memory(argmem: readwrite)
declare void @llvm.lifetime.end.p0(ptr captures(none)) #1

; Function Attrs: noinline
define i64 @bpf_heap_load16(i64 %offset) #0 !dbg !36 {
entry:
  %bpf.heap.array.key.i = alloca i32, align 4, !dbg !39, !bpf.native.alloca !34
  %0 = and i64 %offset, 4194302, !dbg !44
  %bpf.heap.offset.visible = call i64 asm sideeffect "", "=r,0"(i64 %0), !dbg !44
  %1 = trunc i64 %offset to i32, !dbg !44
  %2 = lshr i32 %1, 22, !dbg !44
  %3 = icmp eq i32 %2, 0, !dbg !44
  br i1 %3, label %region.0, label %region.route, !dbg !44

array:                                            ; preds = %region.route
  call void @llvm.lifetime.start.p0(ptr %bpf.heap.array.key.i), !dbg !39
  %4 = and i64 %offset, 4194302, !dbg !39
  %bpf.heap.offset.visible.i = call i64 asm sideeffect "", "=r,0"(i64 %4), !dbg !39
  %5 = trunc i64 %offset to i32, !dbg !39
  %6 = lshr i32 %5, 22, !dbg !39
  %7 = icmp uge i32 %6, 2, !dbg !39
  br i1 %7, label %lookup.i, label %invalid.i, !dbg !39

lookup.i:                                         ; preds = %array
  %8 = sub i32 %6, 2, !dbg !39
  store i32 %8, ptr %bpf.heap.array.key.i, align 4, !dbg !39
  %bpf.heap.array.value.i = call ptr inttoptr (i64 1 to ptr)(ptr @bpf_heap_array, ptr %bpf.heap.array.key.i), !dbg !39
  %9 = icmp ne ptr %bpf.heap.array.value.i, null, !dbg !39
  br i1 %9, label %access.i, label %invalid.i, !dbg !39

access.i:                                         ; preds = %lookup.i
  %10 = getelementptr i8, ptr %bpf.heap.array.value.i, i64 %bpf.heap.offset.visible.i, !dbg !39
  %11 = load i16, ptr %10, align 2, !dbg !39
  %12 = zext i16 %11 to i64, !dbg !39
  call void @llvm.lifetime.end.p0(ptr %bpf.heap.array.key.i), !dbg !39
  br label %bpf_heap_array_load16.exit, !dbg !39

invalid.i:                                        ; preds = %lookup.i, %array
  call void @llvm.lifetime.end.p0(ptr %bpf.heap.array.key.i), !dbg !39
  br label %bpf_heap_array_load16.exit, !dbg !39

bpf_heap_array_load16.exit:                       ; preds = %invalid.i, %access.i
  %13 = phi i64 [ %12, %access.i ], [ 0, %invalid.i ]
  ret i64 %13, !dbg !44

region.route:                                     ; preds = %entry
  switch i32 %2, label %array [
    i32 1, label %region.1
  ], !dbg !44

region.0:                                         ; preds = %entry
  %14 = getelementptr i8, ptr @heap0, i64 %bpf.heap.offset.visible, !dbg !44
  %15 = load i16, ptr %14, align 2, !dbg !44
  %16 = zext i16 %15 to i64, !dbg !44
  ret i64 %16, !dbg !44

region.1:                                         ; preds = %region.route
  %17 = getelementptr i8, ptr @heap1, i64 %bpf.heap.offset.visible, !dbg !44
  %18 = load i16, ptr %17, align 2, !dbg !44
  %19 = zext i16 %18 to i64, !dbg !44
  ret i64 %19, !dbg !44

invalid:                                          ; No predecessors!
  ret i64 0, !dbg !44
}

; Function Attrs: noinline
define i64 @bpf_heap_load32(i64 %offset) #0 !dbg !45 {
entry:
  %bpf.heap.array.key.i = alloca i32, align 4, !dbg !48, !bpf.native.alloca !34
  %0 = and i64 %offset, 4194300, !dbg !53
  %bpf.heap.offset.visible = call i64 asm sideeffect "", "=r,0"(i64 %0), !dbg !53
  %1 = trunc i64 %offset to i32, !dbg !53
  %2 = lshr i32 %1, 22, !dbg !53
  %3 = icmp eq i32 %2, 0, !dbg !53
  br i1 %3, label %region.0, label %region.route, !dbg !53

array:                                            ; preds = %region.route
  call void @llvm.lifetime.start.p0(ptr %bpf.heap.array.key.i), !dbg !48
  %4 = and i64 %offset, 4194300, !dbg !48
  %bpf.heap.offset.visible.i = call i64 asm sideeffect "", "=r,0"(i64 %4), !dbg !48
  %5 = trunc i64 %offset to i32, !dbg !48
  %6 = lshr i32 %5, 22, !dbg !48
  %7 = icmp uge i32 %6, 2, !dbg !48
  br i1 %7, label %lookup.i, label %invalid.i, !dbg !48

lookup.i:                                         ; preds = %array
  %8 = sub i32 %6, 2, !dbg !48
  store i32 %8, ptr %bpf.heap.array.key.i, align 4, !dbg !48
  %bpf.heap.array.value.i = call ptr inttoptr (i64 1 to ptr)(ptr @bpf_heap_array, ptr %bpf.heap.array.key.i), !dbg !48
  %9 = icmp ne ptr %bpf.heap.array.value.i, null, !dbg !48
  br i1 %9, label %access.i, label %invalid.i, !dbg !48

access.i:                                         ; preds = %lookup.i
  %10 = getelementptr i8, ptr %bpf.heap.array.value.i, i64 %bpf.heap.offset.visible.i, !dbg !48
  %11 = load i32, ptr %10, align 4, !dbg !48
  %12 = zext i32 %11 to i64, !dbg !48
  call void @llvm.lifetime.end.p0(ptr %bpf.heap.array.key.i), !dbg !48
  br label %bpf_heap_array_load32.exit, !dbg !48

invalid.i:                                        ; preds = %lookup.i, %array
  call void @llvm.lifetime.end.p0(ptr %bpf.heap.array.key.i), !dbg !48
  br label %bpf_heap_array_load32.exit, !dbg !48

bpf_heap_array_load32.exit:                       ; preds = %invalid.i, %access.i
  %13 = phi i64 [ %12, %access.i ], [ 0, %invalid.i ]
  ret i64 %13, !dbg !53

region.route:                                     ; preds = %entry
  switch i32 %2, label %array [
    i32 1, label %region.1
  ], !dbg !53

region.0:                                         ; preds = %entry
  %14 = getelementptr i8, ptr @heap0, i64 %bpf.heap.offset.visible, !dbg !53
  %15 = load i32, ptr %14, align 4, !dbg !53
  %16 = zext i32 %15 to i64, !dbg !53
  ret i64 %16, !dbg !53

region.1:                                         ; preds = %region.route
  %17 = getelementptr i8, ptr @heap1, i64 %bpf.heap.offset.visible, !dbg !53
  %18 = load i32, ptr %17, align 4, !dbg !53
  %19 = zext i32 %18 to i64, !dbg !53
  ret i64 %19, !dbg !53

invalid:                                          ; No predecessors!
  ret i64 0, !dbg !53
}

; Function Attrs: noinline
define i32 @bpf_heap_store32(i64 %offset, i64 %value) #0 !dbg !54 {
entry:
  %bpf.heap.array.key.i = alloca i32, align 4, !dbg !60, !bpf.native.alloca !34
  %0 = and i64 %offset, 4194300, !dbg !66
  %bpf.heap.offset.visible = call i64 asm sideeffect "", "=r,0"(i64 %0), !dbg !66
  %1 = trunc i64 %offset to i32, !dbg !66
  %2 = lshr i32 %1, 22, !dbg !66
  %3 = icmp eq i32 %2, 0, !dbg !66
  br i1 %3, label %region.0, label %region.route, !dbg !66

array:                                            ; preds = %region.route
  call void @llvm.lifetime.start.p0(ptr %bpf.heap.array.key.i), !dbg !60
  %4 = and i64 %offset, 4194300, !dbg !60
  %bpf.heap.offset.visible.i = call i64 asm sideeffect "", "=r,0"(i64 %4), !dbg !60
  %5 = trunc i64 %offset to i32, !dbg !60
  %6 = lshr i32 %5, 22, !dbg !60
  %7 = icmp uge i32 %6, 2, !dbg !60
  br i1 %7, label %lookup.i, label %invalid.i, !dbg !60

lookup.i:                                         ; preds = %array
  %8 = sub i32 %6, 2, !dbg !60
  store i32 %8, ptr %bpf.heap.array.key.i, align 4, !dbg !60
  %bpf.heap.array.value.i = call ptr inttoptr (i64 1 to ptr)(ptr @bpf_heap_array, ptr %bpf.heap.array.key.i), !dbg !60
  %9 = icmp ne ptr %bpf.heap.array.value.i, null, !dbg !60
  br i1 %9, label %access.i, label %invalid.i, !dbg !60

access.i:                                         ; preds = %lookup.i
  %10 = getelementptr i8, ptr %bpf.heap.array.value.i, i64 %bpf.heap.offset.visible.i, !dbg !60
  %11 = trunc i64 %value to i32, !dbg !60
  store i32 %11, ptr %10, align 4, !dbg !60
  call void @llvm.lifetime.end.p0(ptr %bpf.heap.array.key.i), !dbg !60
  br label %bpf_heap_array_store32.exit, !dbg !60

invalid.i:                                        ; preds = %lookup.i, %array
  call void @llvm.lifetime.end.p0(ptr %bpf.heap.array.key.i), !dbg !60
  br label %bpf_heap_array_store32.exit, !dbg !60

bpf_heap_array_store32.exit:                      ; preds = %invalid.i, %access.i
  ret i32 0, !dbg !66

region.route:                                     ; preds = %entry
  switch i32 %2, label %array [
    i32 1, label %region.1
  ], !dbg !66

region.0:                                         ; preds = %entry
  %12 = getelementptr i8, ptr @heap0, i64 %bpf.heap.offset.visible, !dbg !66
  %13 = trunc i64 %value to i32, !dbg !66
  store i32 %13, ptr %12, align 4, !dbg !66
  ret i32 0, !dbg !66

region.1:                                         ; preds = %region.route
  %14 = getelementptr i8, ptr @heap1, i64 %bpf.heap.offset.visible, !dbg !66
  %15 = trunc i64 %value to i32, !dbg !66
  store i32 %15, ptr %14, align 4, !dbg !66
  ret i32 0, !dbg !66

invalid:                                          ; No predecessors!
  ret i32 0, !dbg !66
}

; Function Attrs: noinline
define i32 @bpf_heap_store64(i64 %offset, i64 %value) #0 !dbg !67 {
entry:
  %bpf.heap.array.key.i = alloca i32, align 4, !dbg !71, !bpf.native.alloca !34
  %0 = and i64 %offset, 4194296, !dbg !77
  %bpf.heap.offset.visible = call i64 asm sideeffect "", "=r,0"(i64 %0), !dbg !77
  %1 = trunc i64 %offset to i32, !dbg !77
  %2 = lshr i32 %1, 22, !dbg !77
  %3 = icmp eq i32 %2, 0, !dbg !77
  br i1 %3, label %region.0, label %region.route, !dbg !77

array:                                            ; preds = %region.route
  call void @llvm.lifetime.start.p0(ptr %bpf.heap.array.key.i), !dbg !71
  %4 = and i64 %offset, 4194296, !dbg !71
  %bpf.heap.offset.visible.i = call i64 asm sideeffect "", "=r,0"(i64 %4), !dbg !71
  %5 = trunc i64 %offset to i32, !dbg !71
  %6 = lshr i32 %5, 22, !dbg !71
  %7 = icmp uge i32 %6, 2, !dbg !71
  br i1 %7, label %lookup.i, label %invalid.i, !dbg !71

lookup.i:                                         ; preds = %array
  %8 = sub i32 %6, 2, !dbg !71
  store i32 %8, ptr %bpf.heap.array.key.i, align 4, !dbg !71
  %bpf.heap.array.value.i = call ptr inttoptr (i64 1 to ptr)(ptr @bpf_heap_array, ptr %bpf.heap.array.key.i), !dbg !71
  %9 = icmp ne ptr %bpf.heap.array.value.i, null, !dbg !71
  br i1 %9, label %access.i, label %invalid.i, !dbg !71

access.i:                                         ; preds = %lookup.i
  %10 = getelementptr i8, ptr %bpf.heap.array.value.i, i64 %bpf.heap.offset.visible.i, !dbg !71
  store i64 %value, ptr %10, align 8, !dbg !71
  call void @llvm.lifetime.end.p0(ptr %bpf.heap.array.key.i), !dbg !71
  br label %bpf_heap_array_store64.exit, !dbg !71

invalid.i:                                        ; preds = %lookup.i, %array
  call void @llvm.lifetime.end.p0(ptr %bpf.heap.array.key.i), !dbg !71
  br label %bpf_heap_array_store64.exit, !dbg !71

bpf_heap_array_store64.exit:                      ; preds = %invalid.i, %access.i
  ret i32 0, !dbg !77

region.route:                                     ; preds = %entry
  switch i32 %2, label %array [
    i32 1, label %region.1
  ], !dbg !77

region.0:                                         ; preds = %entry
  %11 = getelementptr i8, ptr @heap0, i64 %bpf.heap.offset.visible, !dbg !77
  store i64 %value, ptr %11, align 8, !dbg !77
  ret i32 0, !dbg !77

region.1:                                         ; preds = %region.route
  %12 = getelementptr i8, ptr @heap1, i64 %bpf.heap.offset.visible, !dbg !77
  store i64 %value, ptr %12, align 8, !dbg !77
  ret i32 0, !dbg !77

invalid:                                          ; No predecessors!
  ret i32 0, !dbg !77
}

attributes #0 = { noinline "capsule.heap-accessor" }
attributes #1 = { nocallback nofree nosync nounwind willreturn memory(argmem: readwrite) }

!llvm.dbg.cu = !{!2}
!llvm.module.flags = !{!21, !22}

!0 = !DIGlobalVariableExpression(var: !1, expr: !DIExpression())
!1 = distinct !DIGlobalVariable(name: "bpf_heap_array", scope: !2, file: !3, line: 1, type: !13, isLocal: false, isDefinition: true)
!2 = distinct !DICompileUnit(language: DW_LANG_C11, file: !3, producer: "pass contract", isOptimized: false, runtimeVersion: 0, emissionKind: FullDebug, globals: !4)
!3 = !DIFile(filename: "memory-fixed-accessors-contract.c", directory: ".")
!4 = !{!0, !5, !11}
!5 = !DIGlobalVariableExpression(var: !6, expr: !DIExpression())
!6 = distinct !DIGlobalVariable(name: "heap0", linkageName: "heap0", scope: !2, file: !3, type: !7, isLocal: true, isDefinition: true)
!7 = !DICompositeType(tag: DW_TAG_array_type, baseType: !8, size: 33554432, align: 8, elements: !9)
!8 = !DIBasicType(name: "char", size: 8, encoding: DW_ATE_signed_char)
!9 = !{!10}
!10 = !DISubrange(count: 4194304, lowerBound: 0)
!11 = !DIGlobalVariableExpression(var: !12, expr: !DIExpression())
!12 = distinct !DIGlobalVariable(name: "heap1", linkageName: "heap1", scope: !2, file: !3, type: !7, isLocal: true, isDefinition: true)
!13 = distinct !DICompositeType(tag: DW_TAG_structure_type, name: "heap_array_map", file: !3, line: 1, size: 64, elements: !14)
!14 = !{!15}
!15 = !DIDerivedType(tag: DW_TAG_member, name: "max_entries", scope: !13, file: !3, line: 1, baseType: !16, size: 64)
!16 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !17, size: 64)
!17 = !DICompositeType(tag: DW_TAG_array_type, baseType: !18, size: 32, elements: !19)
!18 = !DIBasicType(name: "int", size: 32, encoding: DW_ATE_signed)
!19 = !{!20}
!20 = !DISubrange(count: 1, lowerBound: 0)
!21 = !{i32 2, !"Dwarf Version", i32 4}
!22 = !{i32 2, !"Debug Info Version", i32 3}
!23 = distinct !DISubprogram(name: "bpf_heap_load8", linkageName: "bpf_heap_load8", scope: null, file: !3, type: !24, spFlags: DISPFlagDefinition, unit: !2, retainedNodes: !27)
!24 = !DISubroutineType(types: !25)
!25 = !{!26, !26}
!26 = !DIBasicType(name: "unsigned long long", size: 64, encoding: DW_ATE_unsigned)
!27 = !{!28}
!28 = !DILocalVariable(name: "offset", arg: 1, scope: !23, file: !3, type: !26)
!29 = !DILocation(line: 0, scope: !30, inlinedAt: !33)
!30 = distinct !DISubprogram(name: "bpf_heap_array_load8", linkageName: "bpf_heap_array_load8", scope: null, file: !3, type: !24, spFlags: DISPFlagDefinition, unit: !2, retainedNodes: !31)
!31 = !{!32}
!32 = !DILocalVariable(name: "offset", arg: 1, scope: !30, file: !3, type: !26)
!33 = distinct !DILocation(line: 0, scope: !23)
!34 = !{}
!35 = !DILocation(line: 0, scope: !23)
!36 = distinct !DISubprogram(name: "bpf_heap_load16", linkageName: "bpf_heap_load16", scope: null, file: !3, type: !24, spFlags: DISPFlagDefinition, unit: !2, retainedNodes: !37)
!37 = !{!38}
!38 = !DILocalVariable(name: "offset", arg: 1, scope: !36, file: !3, type: !26)
!39 = !DILocation(line: 0, scope: !40, inlinedAt: !43)
!40 = distinct !DISubprogram(name: "bpf_heap_array_load16", linkageName: "bpf_heap_array_load16", scope: null, file: !3, type: !24, spFlags: DISPFlagDefinition, unit: !2, retainedNodes: !41)
!41 = !{!42}
!42 = !DILocalVariable(name: "offset", arg: 1, scope: !40, file: !3, type: !26)
!43 = distinct !DILocation(line: 0, scope: !36)
!44 = !DILocation(line: 0, scope: !36)
!45 = distinct !DISubprogram(name: "bpf_heap_load32", linkageName: "bpf_heap_load32", scope: null, file: !3, type: !24, spFlags: DISPFlagDefinition, unit: !2, retainedNodes: !46)
!46 = !{!47}
!47 = !DILocalVariable(name: "offset", arg: 1, scope: !45, file: !3, type: !26)
!48 = !DILocation(line: 0, scope: !49, inlinedAt: !52)
!49 = distinct !DISubprogram(name: "bpf_heap_array_load32", linkageName: "bpf_heap_array_load32", scope: null, file: !3, type: !24, spFlags: DISPFlagDefinition, unit: !2, retainedNodes: !50)
!50 = !{!51}
!51 = !DILocalVariable(name: "offset", arg: 1, scope: !49, file: !3, type: !26)
!52 = distinct !DILocation(line: 0, scope: !45)
!53 = !DILocation(line: 0, scope: !45)
!54 = distinct !DISubprogram(name: "bpf_heap_store32", linkageName: "bpf_heap_store32", scope: null, file: !3, type: !55, spFlags: DISPFlagDefinition, unit: !2, retainedNodes: !57)
!55 = !DISubroutineType(types: !56)
!56 = !{!18, !26, !26}
!57 = !{!58, !59}
!58 = !DILocalVariable(name: "offset", arg: 1, scope: !54, file: !3, type: !26)
!59 = !DILocalVariable(name: "value", arg: 2, scope: !54, file: !3, type: !26)
!60 = !DILocation(line: 0, scope: !61, inlinedAt: !65)
!61 = distinct !DISubprogram(name: "bpf_heap_array_store32", linkageName: "bpf_heap_array_store32", scope: null, file: !3, type: !55, spFlags: DISPFlagDefinition, unit: !2, retainedNodes: !62)
!62 = !{!63, !64}
!63 = !DILocalVariable(name: "offset", arg: 1, scope: !61, file: !3, type: !26)
!64 = !DILocalVariable(name: "value", arg: 2, scope: !61, file: !3, type: !26)
!65 = distinct !DILocation(line: 0, scope: !54)
!66 = !DILocation(line: 0, scope: !54)
!67 = distinct !DISubprogram(name: "bpf_heap_store64", linkageName: "bpf_heap_store64", scope: null, file: !3, type: !55, spFlags: DISPFlagDefinition, unit: !2, retainedNodes: !68)
!68 = !{!69, !70}
!69 = !DILocalVariable(name: "offset", arg: 1, scope: !67, file: !3, type: !26)
!70 = !DILocalVariable(name: "value", arg: 2, scope: !67, file: !3, type: !26)
!71 = !DILocation(line: 0, scope: !72, inlinedAt: !76)
!72 = distinct !DISubprogram(name: "bpf_heap_array_store64", linkageName: "bpf_heap_array_store64", scope: null, file: !3, type: !55, spFlags: DISPFlagDefinition, unit: !2, retainedNodes: !73)
!73 = !{!74, !75}
!74 = !DILocalVariable(name: "offset", arg: 1, scope: !72, file: !3, type: !26)
!75 = !DILocalVariable(name: "value", arg: 2, scope: !72, file: !3, type: !26)
!76 = distinct !DILocation(line: 0, scope: !67)
!77 = !DILocation(line: 0, scope: !67)
