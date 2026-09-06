source_filename = "stackify-rejected-borrowed-without-btf.ll"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpfel"

%fiber_control = type { i32, i32, i64, i64, i64, i32, i32 }
%config = type { i32, i32, i32, i32, i32, i32, i32, i32, i32, i32, i32, i32, i64 }

@bpf_capsule_fibers = global [1 x %fiber_control] zeroinitializer, section ".bss.bpfctrl", align 8
@bpf_capsule_config = constant %config zeroinitializer, section ".rodata.bpfconfig", align 4

define void @borrowed_without_type() !bpf.capsule !0 {
entry:
  ret void
}

define i32 @start(ptr %context, i32 %fiber) section "xdp" !bpf.native !0 {
entry:
  call void @borrowed_without_type() [ "bpf.capsule.call"(i32 %fiber, ptr %context) ]
  ret i32 2
}

!0 = !{}
