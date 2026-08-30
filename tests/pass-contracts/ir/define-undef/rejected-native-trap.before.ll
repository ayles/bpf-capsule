source_filename = "define-undef-native-trap.ll"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpfel"

define i32 @native_trap() !bpf.native !0 {
entry:
  unreachable
}

!0 = !{}
