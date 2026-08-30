source_filename = "softfloat-capsule-boundary.ll"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpfel"

@result_bits = global i32 0, align 4, !bpf.native !0

define void @native_entry(i32 %fiber) section "xdp" !bpf.native !0 {
entry:
  %0 = call noundef i32 @capsule_root(i32 noundef 1065353216) [ "bpf.capsule.call"(i32 %fiber) ], !contract !0
  store i32 %0, ptr @result_bits, align 4
  ret void
}

define i32 @capsule_root(i32 noundef %value) !contract !0 !bpf.capsule !0 {
entry:
  ret i32 %value
}

!llvm.module.flags = !{!1}

!0 = !{}
!1 = !{i32 1, !"bpf.capsule.classes", i32 1}
