source_filename = "capsule-domains-owned-global.ll"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpfel"

@owned = global i32 0, !bpf.capsule.owned !0, !bpf.native !0, !bpf.capsule !0

define i32 @entry() section "xdp" !bpf.native !0 {
entry:
  %native = load i32, ptr @owned, align 4
  %managed = call i32 @capsule_root() [ "bpf.capsule.call"(i32 0) ]
  %result = add i32 %native, %managed
  ret i32 %result
}

define i32 @capsule_root() !bpf.capsule !0 {
entry:
  %value = load i32, ptr @owned, align 4
  ret i32 %value
}

!llvm.module.flags = !{!1}

!0 = !{}
!1 = !{i32 1, !"bpf.capsule.classes", i32 1}
