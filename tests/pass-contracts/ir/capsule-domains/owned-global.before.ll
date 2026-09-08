source_filename = "capsule-domains-owned-global.ll"
target triple = "bpfel"

@owned = global i32 0, !bpf.capsule.owned !0

define i32 @entry() section "xdp" {
entry:
  %native = load i32, ptr @owned, align 4
  %managed = call i32 @capsule_root() [ "bpf.capsule.call"(i32 0) ]
  %result = add i32 %native, %managed
  ret i32 %result
}

define i32 @capsule_root() {
entry:
  %value = load i32, ptr @owned, align 4
  ret i32 %value
}

!0 = !{}
