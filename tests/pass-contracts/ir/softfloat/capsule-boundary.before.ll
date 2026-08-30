source_filename = "softfloat-capsule-boundary.ll"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpfel"

@result_bits = global i32 0, align 4

define void @native_entry(i32 %fiber) section "xdp" !bpf.native !0 {
entry:
  %value = bitcast i32 1065353216 to float
  %result = call noundef nofpclass(nan) float @capsule_root(float noundef nofpclass(nan) %value) [ "bpf.capsule.call"(i32 %fiber) ], !contract !0
  %bits = bitcast float %result to i32
  store i32 %bits, ptr @result_bits, align 4
  ret void
}

define nofpclass(nan) float @capsule_root(float noundef nofpclass(nan) %value) !contract !0 !bpf.capsule !0 {
entry:
  ret float %value
}

!0 = !{}
