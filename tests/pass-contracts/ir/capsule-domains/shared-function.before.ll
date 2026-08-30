source_filename = "capsule-domains-shared-function.ll"
target triple = "bpfel"

define i32 @entry(i32 %value) section "xdp" {
entry:
  %native = call i32 @shared(i32 %value)
  %managed = call i32 @capsule_root(i32 %value) [ "bpf.capsule.call"(i32 0) ]
  %result = add i32 %native, %managed
  ret i32 %result
}

define i32 @capsule_root(i32 %value) {
entry:
  %result = call i32 @shared(i32 %value)
  ret i32 %result
}

define i32 @shared(i32 %value) {
entry:
  ret i32 %value
}
