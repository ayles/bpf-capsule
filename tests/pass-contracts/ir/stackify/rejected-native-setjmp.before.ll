source_filename = "stackify-rejected-native-setjmp.ll"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpfel"

; Function Attrs: returns_twice
declare i32 @__bpf_capsule_setjmp(ptr) #0

define i32 @native_setjmp(ptr %env) section "xdp" {
entry:
  %result = call i32 @__bpf_capsule_setjmp(ptr %env)
  ret i32 %result
}

attributes #0 = { returns_twice }
