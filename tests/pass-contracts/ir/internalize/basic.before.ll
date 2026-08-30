source_filename = "internalize.ll"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpfel"

define i32 @ordinary() {
entry:
  ret i32 1
}

define internal i32 @already_internal() {
entry:
  ret i32 2
}

define i32 @entry_program() section "syscall" {
entry:
  ret i32 0
}

define i32 @__bpf_capsule_trampoline_step() #0 {
entry:
  ret i32 0
}

define i64 @bpf_heap_load64(i64 %address) #1 {
entry:
  ret i64 %address
}

define i64 @__bpf_i2d(i64 %value) #2 {
entry:
  ret i64 %value
}

declare i32 @external_declaration()

attributes #0 = { "capsule.trampoline" }
attributes #1 = { "capsule.heap-accessor" }
attributes #2 = { "capsule.nosuspend" }
