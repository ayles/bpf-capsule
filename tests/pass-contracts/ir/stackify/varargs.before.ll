source_filename = "stackify-varargs.ll"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpfel"

%fiber_control = type { i32, i32, i64, i64, i64, i32, i32 }
%config = type { i32, i32, i32, i32, i32, i32, i32, i32, i32, i32, i32, i32, i64 }
%wide = type { i64, i64, i64 }

@bpf_capsule_fibers = global [1 x %fiber_control] zeroinitializer, section ".bss.bpfctrl", align 8
@bpf_capsule_config = constant %config { i32 0, i32 4096, i32 0, i32 0, i32 1, i32 4096, i32 1, i32 0, i32 1, i32 0, i32 1112556353, i32 5, i64 0 }, section ".rodata.bpfconfig", align 4
@sum_pointer = global ptr @sum_values
@wide_direct = global %wide { i64 4, i64 5, i64 6 }, align 8
@wide_indirect = global %wide { i64 10, i64 11, i64 12 }, align 8

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

define i64 @sum_values(i32 %fixed, ...) !bpf.capsule !0 {
entry:
  %list = alloca ptr, align 8
  %copy = alloca ptr, align 8
  call void @llvm.va_start.p0(ptr %list)
  %first = va_arg ptr %list, i32
  call void @llvm.va_copy.p0(ptr %copy, ptr %list)
  %second = va_arg ptr %copy, i128
  %third.pointer = va_arg ptr %copy, ptr
  %third = load %wide, ptr %third.pointer, align 8
  %fourth = va_arg ptr %copy, ptr
  call void @llvm.va_end.p0(ptr %copy)
  call void @llvm.va_end.p0(ptr %list)
  %second.low = trunc i128 %second to i64
  %third.middle = extractvalue %wide %third, 1
  %fourth.bits = ptrtoint ptr %fourth to i64
  %first.wide = zext i32 %first to i64
  %fixed.wide = zext i32 %fixed to i64
  %a = add i64 %fixed.wide, %first.wide
  %b = add i64 %a, %second.low
  %c = add i64 %b, %third.middle
  %result = add i64 %c, %fourth.bits
  ret i64 %result
}

define i64 @root(ptr %pointer) !bpf.capsule !0 {
entry:
  %direct = call i64 (i32, ...) @sum_values(i32 1, i32 2, i128 3, ptr byval(%wide) align 8 @wide_direct, ptr %pointer)
  %callee = load ptr, ptr @sum_pointer, align 8
  %indirect = call i64 (i32, ...) %callee(i32 7, i32 8, i128 9, ptr byval(%wide) align 8 @wide_indirect, ptr %pointer)
  %result = add i64 %direct, %indirect
  ret i64 %result
}

define i64 @start(i32 %fiber, ptr %pointer) section "syscall" !bpf.native !0 {
entry:
  %result = call i64 @root(ptr %pointer) [ "bpf.capsule.call"(i32 %fiber) ]
  ret i64 %result
}

; Function Attrs: nocallback nofree nosync nounwind willreturn
declare void @llvm.va_start.p0(ptr) #1

; Function Attrs: nocallback nofree nosync nounwind willreturn
declare void @llvm.va_end.p0(ptr) #1

; Function Attrs: nocallback nofree nosync nounwind willreturn
declare void @llvm.va_copy.p0(ptr, ptr) #1

attributes #0 = { "capsule.trampoline" }
attributes #1 = { nocallback nofree nosync nounwind willreturn }

!0 = !{}
