source_filename = "capsule-domains.ll"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpfel"

@native_state = global i32 1, !bpf.native !0
@capsule_state = global i32 2, !bpf.capsule !0
@shared_state = global i32 3, section ".data.shared", !bpf.native !0, !bpf.capsule !0
@callback_table = global [1 x ptr] [ptr @capsule_callback]

define i32 @entry(i32 %value) section "xdp" !bpf.native !0 {
entry:
  %native = load i32, ptr @native_state, align 4
  %managed = call i32 @capsule_root(i32 %value) [ "bpf.capsule.call"(i32 0) ]
  %shared = load i32, ptr @shared_state, align 4
  %sum = add i32 %native, %managed
  %result = add i32 %sum, %shared
  ret i32 %result
}

define i32 @capsule_root(i32 %value) !bpf.capsule !0 {
entry:
  %state = load i32, ptr @capsule_state, align 4
  %shared = load i32, ptr @shared_state, align 4
  %leaf = call i32 @capsule_leaf(i32 %value)
  %sum = add i32 %state, %shared
  %result = add i32 %sum, %leaf
  ret i32 %result
}

define i32 @capsule_leaf(i32 %value) !bpf.capsule !0 {
entry:
  ret i32 %value
}

define i32 @capsule_callback(i32 %value) !bpf.capsule !0 {
entry:
  %result = add i32 %value, 1
  ret i32 %result
}

!llvm.module.flags = !{!1}

!0 = !{}
!1 = !{i32 1, !"bpf.capsule.classes", i32 1}
