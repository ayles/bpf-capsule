source_filename = "capsule-domains-nested-boundary.ll"
target triple = "bpfel"

define i32 @entry(i32 %value) section "xdp" {
entry:
  %result = call i32 @outer(i32 %value) [ "bpf.capsule.call"(i32 0) ]
  ret i32 %result
}

define i32 @outer(i32 %value) {
entry:
  %result = call i32 @inner(i32 %value) [ "bpf.capsule.call"(i32 0) ]
  ret i32 %result
}

define i32 @inner(i32 %value) {
entry:
  ret i32 %value
}
